// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// protoc-gen-kacho-permissions emits a deterministic JSON catalog
// (`gen/permission_catalog.json`) of every gRPC RPC across the kacho-proto tree,
// annotated with the four `kacho.iam.authz.v1.*` MethodOptions.
//
// Pipeline:
//
//  1. buf generate invokes this plugin once for the whole input set.
//  2. The plugin walks every FileDescriptor → ServiceDescriptor → MethodDescriptor.
//  3. For each method it reads the four extensions
//     (`permission`, `required_relation`, `scope_extractor`, `required_acr_min`)
//     via proto.GetExtension on the generated MethodOptions.
//  4. Rows missing the required `permission` annotation are emitted with
//     empty-string fields so the catalog remains complete during the rollout
//     window; validation errors are written to stderr (and to the generated
//     `permission_catalog_warnings.txt` for CI inspection).
//  5. When the environment variable `KACHO_PERMISSIONS_STRICT=1` is set the
//     plugin fails the build (CodeGeneratorResponse.Error) listing every
//     offending FQN — used by the dedicated `verify-permissions-coverage` CI
//     job once every RPC across the polyrepo is annotated.
//  6. `<exempt>` is a recognised opt-out value for RPCs that intentionally
//     bypass authz (e.g. internal-port OperationService.Get); the row is
//     still emitted into the catalog so downstream tooling can verify
//     coverage.
//  7. Catalog rows are sorted by FQN ascending — deterministic golden-diff.
//  8. Output: `permission_catalog.json` (+ `permission_catalog_warnings.txt`
//     when annotations are missing) next to the gen/ tree.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	authzv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/iam/authz/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// CatalogEntry is one row of permission_catalog.json. Field tags are the
// normative wire format consumed by the gateway authz middleware.
type CatalogEntry struct {
	FQN              string         `json:"fqn"`
	Permission       string         `json:"permission"`
	RequiredRelation string         `json:"required_relation"`
	ScopeExtractor   ScopeExtractor `json:"scope_extractor"`
	RequiredAcrMin   string         `json:"required_acr_min,omitempty"`
}

// ScopeExtractor mirrors authzv1.ScopeExtractor on the JSON side.
type ScopeExtractor struct {
	ObjectType       string `json:"object_type"`
	FromRequestField string `json:"from_request_field"`
	// ObjectTypeFromRequestField — name of the request field carrying the FGA
	// object type at request time (scope-polymorphic RPCs, e.g.
	// AccessBindingService.ListByResource → "resource_type"). Empty for the
	// fixed-scope majority; omitted from JSON when empty.
	ObjectTypeFromRequestField string `json:"object_type_from_request_field,omitempty"`
}

const (
	// DefaultRequiredAcrMin is the value emitted into the catalog when the
	// proto omits the required_acr_min option.
	DefaultRequiredAcrMin = "2"

	// ExemptSentinel is the literal value an RPC sets to opt out of authz
	// (e.g. `option (kacho.iam.authz.v1.permission) = "<exempt>";`). The row
	// still appears in the catalog with this exact string for coverage audit.
	ExemptSentinel = "<exempt>"

	// CatalogOutputPath is the primary file emitted by this plugin, relative
	// to the buf.gen.yaml `out:` directory.
	CatalogOutputPath = "permission_catalog.json"

	// WarningsOutputPath is emitted when one or more RPCs lack required
	// annotations. The file lists offending FQNs and the missing options —
	// suitable for human review and CI grep. Absent when the catalog is clean.
	WarningsOutputPath = "permission_catalog_warnings.txt"

	// StrictEnv toggles hard build failure on missing annotations. Set to
	// "1" by the dedicated `verify-permissions-coverage` CI job; un-set while
	// some RPCs are still being annotated.
	StrictEnv = "KACHO_PERMISSIONS_STRICT"

	// PrimaryFile is the proto file whose presence in `req.FileToGenerate`
	// triggers catalog emission. buf invokes the plugin once per package
	// (the same plugin binary is fed N times, one per package being
	// regenerated); each invocation sees the FULL transitive descriptor set
	// but is "responsible" only for `FileToGenerate`. Without this guard
	// every invocation would emit the same `permission_catalog.json`,
	// causing buf duplicate-file-name conflicts that drop the output entirely.
	// Anchoring on a single primary file gives us exactly one emitter.
	PrimaryFile = "kacho/iam/authz/catalog/v1/permissions_catalog_root.proto"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "protoc-gen-kacho-permissions: %v\n", err)
		os.Exit(1)
	}
}

func run(stdin io.Reader, stdout io.Writer) error {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read CodeGeneratorRequest: %w", err)
	}
	req := &pluginpb.CodeGeneratorRequest{}
	if err := proto.Unmarshal(raw, req); err != nil {
		return fmt.Errorf("unmarshal CodeGeneratorRequest: %w", err)
	}

	if !shouldEmit(req) {
		// Not the primary invocation — produce an empty CodeGeneratorResponse
		// so buf treats this plugin as a no-op for this package.
		return writeEmptyResponse(stdout)
	}

	entries, warnings := collectEntries(req)

	// Stable ordering — deterministic golden diff.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FQN < entries[j].FQN
	})
	sort.Strings(warnings)

	resp := &pluginpb.CodeGeneratorResponse{}

	if strict() && len(warnings) > 0 {
		// Strict mode (dedicated CI job). Fail the build with every offending
		// FQN aggregated into a single error message.
		header := fmt.Sprintf(
			"strict permission catalog check failed (%d RPC(s) missing required annotations):",
			len(warnings),
		)
		resp.Error = proto.String(header + "\n" + strings.Join(warnings, "\n"))
	} else {
		out, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal catalog json: %w", err)
		}
		// Append trailing newline for POSIX-friendly diff.
		out = append(out, '\n')

		files := []*pluginpb.CodeGeneratorResponse_File{{
			Name:    proto.String(CatalogOutputPath),
			Content: proto.String(string(out)),
		}}

		if len(warnings) > 0 {
			// Non-strict: surface the warnings as a generated file so CI
			// jobs can grep and humans can review. The file is removed
			// (by the same plugin run) when no warnings exist.
			warningsContent := "# protoc-gen-kacho-permissions warnings\n" +
				"# RPCs missing required `(kacho.iam.authz.v1.*)` options.\n" +
				"# Once annotated, this file disappears on the next `buf generate`.\n" +
				"# Set KACHO_PERMISSIONS_STRICT=1 to fail the build instead.\n\n" +
				strings.Join(warnings, "\n") + "\n"
			files = append(files, &pluginpb.CodeGeneratorResponse_File{
				Name:    proto.String(WarningsOutputPath),
				Content: proto.String(warningsContent),
			})

			// Also print to plugin stderr so `buf generate` prints them
			// inline.
			fmt.Fprintf(os.Stderr,
				"protoc-gen-kacho-permissions: %d warning(s) — see gen/%s\n",
				len(warnings), WarningsOutputPath)
		}

		resp.File = files
	}

	// Advertise proto3-optional support (required by newer protoc / buf).
	resp.SupportedFeatures = proto.Uint64(uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL))

	respBytes, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal CodeGeneratorResponse: %w", err)
	}
	if _, err := stdout.Write(respBytes); err != nil {
		return fmt.Errorf("write CodeGeneratorResponse: %w", err)
	}
	return nil
}

// strict reports whether the plugin should fail the build on missing
// annotations.
func strict() bool {
	return os.Getenv(StrictEnv) == "1"
}

// shouldEmit returns true if this plugin invocation is the "primary" one
// — i.e. `PrimaryFile` is in the FileToGenerate list. See PrimaryFile godoc
// for why this gate is necessary under buf v2.
func shouldEmit(req *pluginpb.CodeGeneratorRequest) bool {
	for _, f := range req.GetFileToGenerate() {
		if f == PrimaryFile {
			return true
		}
	}
	return false
}

// writeEmptyResponse writes an empty CodeGeneratorResponse for non-primary
// invocations.
func writeEmptyResponse(stdout io.Writer) error {
	resp := &pluginpb.CodeGeneratorResponse{
		SupportedFeatures: proto.Uint64(uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)),
	}
	out, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal empty CodeGeneratorResponse: %w", err)
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write empty CodeGeneratorResponse: %w", err)
	}
	return nil
}

// collectEntries walks every method in every file in the request and produces
// a catalog row per RPC plus an optional warning per RPC with missing
// annotations.
//
// buf passes the FULL transitive descriptor set in `req.ProtoFile` regardless
// of which files are listed in `req.FileToGenerate` — by iterating the whole
// set we get cross-file coverage (e.g. a vpc regen still reflects new compute
// RPCs).
func collectEntries(req *pluginpb.CodeGeneratorRequest) ([]CatalogEntry, []string) {
	// Touch the registry so the import isn't vestigial. proto.GetExtension
	// resolves the extension type info from the registered extension at
	// import-time (`authzv1.E_Permission`, etc.).
	_ = protoregistry.GlobalTypes

	var entries []CatalogEntry
	var warnings []string

	for _, fd := range req.GetProtoFile() {
		pkg := fd.GetPackage()
		for _, svc := range fd.GetService() {
			svcFQN := pkg + "." + svc.GetName()
			for _, m := range svc.GetMethod() {
				rpcFQN := svcFQN + "/" + m.GetName()
				entry, warning := extractEntry(rpcFQN, m.GetOptions())
				entries = append(entries, entry)
				if warning != "" {
					warnings = append(warnings, warning)
				}
			}
		}
	}
	return entries, warnings
}

// extractEntry pulls the four authz options from a MethodOptions proto and
// returns a catalog row plus an optional warning string.
//
// Validation rules:
//   - permission              — required, non-empty (or literal `<exempt>`)
//   - required_relation       — required, non-empty (waived for exempt)
//   - scope_extractor         — required, non-empty object_type + from_request_field (waived for exempt)
//   - required_acr_min        — optional (default `"2"` injected here)
//
// A row is ALWAYS emitted (with empty strings for missing fields), so the
// catalog is exhaustive; the warning string drives the strict-mode failure
// and the human-readable warnings file.
func extractEntry(rpcFQN string, opts *descriptorpb.MethodOptions) (CatalogEntry, string) {
	permission := getStringExt(opts, authzv1.E_Permission)
	requiredRelation := getStringExt(opts, authzv1.E_RequiredRelation)
	requiredAcrMin := getStringExt(opts, authzv1.E_RequiredAcrMin)
	scope := getScopeExt(opts, authzv1.E_ScopeExtractor)

	entry := CatalogEntry{
		FQN:              rpcFQN,
		Permission:       permission,
		RequiredRelation: requiredRelation,
		ScopeExtractor:   scope,
		RequiredAcrMin:   requiredAcrMin,
	}

	if permission == ExemptSentinel {
		// Exempt RPC — no required-fields check.
		return entry, ""
	}

	if permission == "" {
		return entry, fmt.Sprintf(
			"%s: missing required option (kacho.iam.authz.v1.permission)",
			rpcFQN,
		)
	}

	var problems []string
	if requiredRelation == "" {
		problems = append(problems, "(kacho.iam.authz.v1.required_relation)")
	}
	if scope.ObjectType == "" {
		problems = append(problems, "(kacho.iam.authz.v1.scope_extractor).object_type")
	}
	if scope.FromRequestField == "" {
		problems = append(problems, "(kacho.iam.authz.v1.scope_extractor).from_request_field")
	}
	if len(problems) > 0 {
		return entry, fmt.Sprintf(
			"%s: missing required option(s) %s",
			rpcFQN,
			strings.Join(problems, ", "),
		)
	}

	if entry.RequiredAcrMin == "" {
		entry.RequiredAcrMin = DefaultRequiredAcrMin
	}
	return entry, ""
}

// getStringExt reads a string-typed extension off a MethodOptions, returning
// "" when the extension is not set or carries a non-string value.
func getStringExt(opts *descriptorpb.MethodOptions, ext protoreflect.ExtensionType) string {
	if opts == nil || !proto.HasExtension(opts, ext) {
		return ""
	}
	v := proto.GetExtension(opts, ext)
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// getScopeExt reads the ScopeExtractor message extension. Returns a zero
// ScopeExtractor when unset or type-mismatched.
func getScopeExt(opts *descriptorpb.MethodOptions, ext protoreflect.ExtensionType) ScopeExtractor {
	if opts == nil || !proto.HasExtension(opts, ext) {
		return ScopeExtractor{}
	}
	v := proto.GetExtension(opts, ext)
	sx, ok := v.(*authzv1.ScopeExtractor)
	if !ok || sx == nil {
		return ScopeExtractor{}
	}
	return ScopeExtractor{
		ObjectType:                 sx.GetObjectType(),
		FromRequestField:           sx.GetFromRequestField(),
		ObjectTypeFromRequestField: sx.GetObjectTypeFromRequestField(),
	}
}
