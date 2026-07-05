// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// protoc-gen-kacho-rest-routes эмитит статическую таблицу REST-path -> gRPC-FQN
// (`internal/middleware/rest_route_table_gen.go`) из аннотаций
// `option (google.api.http)` каждого RPC всего proto-дерева Kachō.
//
// Зачем: authz-middleware api-gateway на HTTP-пути обязана превратить входящий
// REST-запрос (`POST /iam/v1/accounts`) в канонический gRPC-FQN
// (`kacho.cloud.iam.v1.AccountService/Create`), чтобы найти метод в
// permission-каталоге. Без соответствия path->FQN каждый REST-вызов упирается в
// «no entry for method» и отклоняется. Таблица должна покрывать ВСЕ
// http-аннотированные RPC всех доменов — поэтому генерируется здесь, где
// api-gateway видит полный набор.
//
// Механика (та же, что у protoc-gen-kacho-permissions):
//
//  1. buf generate вызывает плагин один раз на весь ассемблированный образ.
//  2. Плагин обходит каждый FileDescriptor -> ServiceDescriptor ->
//     MethodDescriptor и читает расширение `google.api.http` через
//     proto.GetExtension (тип HttpRule зарегистрирован blank-импортом пакета
//     annotations).
//  3. Из HttpRule извлекается primary-binding и все вложенные
//     additional_bindings: (httpMethod, pathTemplate). `:verb`-суффиксы и
//     `{field}`-плейсхолдеры сохраняются как есть — их разбирает matchTemplate.
//  4. Метод без http-аннотации в таблицу не попадает (gRPC-only внутренние RPC).
//  5. Строки сортируются по (Template, Method) — детерминированный golden-diff,
//     повторный прогон дает нулевой diff.
//  6. Выход — готовый Go-файл `rest_route_table_gen.go` (пакет middleware),
//     прогнанный через go/format.
//
// Как у permissions-каталога, эмиссия «прибита» к anchor-файлу
// permissions_catalog_root.proto: buf вызывает плагин по разу на каждый пакет,
// но образ каждый раз полный — без гейта каждый вызов эмитил бы одинаковый файл
// и buf уронил бы вывод на duplicate-file-name.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"os"
	"sort"
	"strings"

	annotations "google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// Route — одна строка таблицы: (httpMethod, pathTemplate) -> FQN.
type Route struct {
	Method   string
	Template string
	FQN      string
}

const (
	// OutputPath — имя эмитируемого файла относительно каталога `out:` из
	// buf.gen.yaml. Сборочный скрипт копирует его в internal/middleware/.
	OutputPath = "rest_route_table_gen.go"

	// PrimaryFile — anchor: плагин эмитит таблицу только когда это имя есть в
	// CodeGeneratorRequest.FileToGenerate. Иначе (buf зовет плагин по разу на
	// пакет) каждый вызов эмитил бы одинаковый файл -> duplicate-file-name.
	PrimaryFile = "kacho/iam/authz/catalog/v1/permissions_catalog_root.proto"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "protoc-gen-kacho-rest-routes: %v\n", err)
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
		// Не primary-вызов — отдаем пустой ответ (no-op для этого пакета).
		return writeResponse(stdout, &pluginpb.CodeGeneratorResponse{})
	}

	routes := collectRoutes(req)
	sortRoutes(routes)

	src, err := render(routes)
	if err != nil {
		return err
	}

	resp := &pluginpb.CodeGeneratorResponse{
		File: []*pluginpb.CodeGeneratorResponse_File{{
			Name:    proto.String(OutputPath),
			Content: proto.String(string(src)),
		}},
	}
	return writeResponse(stdout, resp)
}

// shouldEmit — этот вызов primary (anchor в FileToGenerate)?
func shouldEmit(req *pluginpb.CodeGeneratorRequest) bool {
	for _, f := range req.GetFileToGenerate() {
		if f == PrimaryFile {
			return true
		}
	}
	return false
}

// writeResponse маршалит и пишет CodeGeneratorResponse, объявляя поддержку
// proto3-optional (требует свежий buf/protoc).
func writeResponse(stdout io.Writer, resp *pluginpb.CodeGeneratorResponse) error {
	resp.SupportedFeatures = proto.Uint64(uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL))
	out, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal CodeGeneratorResponse: %w", err)
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write CodeGeneratorResponse: %w", err)
	}
	return nil
}

// collectRoutes обходит весь образ и собирает по одной строке на каждый
// http-binding каждого RPC. buf передает ПОЛНЫЙ транзитивный descriptor-set в
// req.ProtoFile независимо от FileToGenerate — поэтому таблица покрывает все
// домены одним прогоном.
func collectRoutes(req *pluginpb.CodeGeneratorRequest) []Route {
	var routes []Route
	for _, fd := range req.GetProtoFile() {
		pkg := fd.GetPackage()
		for _, svc := range fd.GetService() {
			svcFQN := pkg + "." + svc.GetName()
			for _, m := range svc.GetMethod() {
				fqn := svcFQN + "/" + m.GetName()
				for _, b := range httpBindings(m.GetOptions()) {
					routes = append(routes, Route{
						Method:   b.method,
						Template: b.path,
						FQN:      fqn,
					})
				}
			}
		}
	}
	return routes
}

// binding — извлеченная из HttpRule пара (метод, path).
type binding struct {
	method string
	path   string
}

// httpBindings возвращает primary-binding плюс все additional_bindings метода.
// Метод без `option (google.api.http)` дает пустой срез (в таблицу не попадает).
func httpBindings(opts *descriptorpb.MethodOptions) []binding {
	rule := httpRule(opts)
	if rule == nil {
		return nil
	}
	var out []binding
	if b, ok := patternBinding(rule); ok {
		out = append(out, b)
	}
	for _, ab := range rule.GetAdditionalBindings() {
		if b, ok := patternBinding(ab); ok {
			out = append(out, b)
		}
	}
	return out
}

// httpRule читает расширение google.api.http с MethodOptions. Возвращает nil,
// если аннотации нет или тип не совпал.
func httpRule(opts *descriptorpb.MethodOptions) *annotations.HttpRule {
	if opts == nil || !proto.HasExtension(opts, annotations.E_Http) {
		return nil
	}
	v := proto.GetExtension(opts, annotations.E_Http)
	rule, ok := v.(*annotations.HttpRule)
	if !ok {
		return nil
	}
	return rule
}

// patternBinding вытаскивает (метод, path) из oneof-паттерна HttpRule. Для
// custom-паттерна метод берется из kind (в верхнем регистре).
func patternBinding(rule *annotations.HttpRule) (binding, bool) {
	switch p := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		return binding{"GET", p.Get}, true
	case *annotations.HttpRule_Put:
		return binding{"PUT", p.Put}, true
	case *annotations.HttpRule_Post:
		return binding{"POST", p.Post}, true
	case *annotations.HttpRule_Delete:
		return binding{"DELETE", p.Delete}, true
	case *annotations.HttpRule_Patch:
		return binding{"PATCH", p.Patch}, true
	case *annotations.HttpRule_Custom:
		if p.Custom == nil {
			return binding{}, false
		}
		return binding{strings.ToUpper(p.Custom.GetKind()), p.Custom.GetPath()}, true
	default:
		return binding{}, false
	}
}

// sortRoutes задает детерминированный порядок: по Template, затем по Method.
// Строковое сравнение Template дает «path-then-method» группировку (короткий
// префикс раньше вложенного, `:verb` после базового пути).
func sortRoutes(routes []Route) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Template != routes[j].Template {
			return routes[i].Template < routes[j].Template
		}
		return routes[i].Method < routes[j].Method
	})
}

// fileHeader — шапка и объявления генерируемого файла. Текст стабилен: меняется
// только состав строк таблицы, поэтому golden-diff остается узким.
const fileHeader = `// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Code generated by the route-table extractor. DO NOT EDIT.
//
// rest_route_table_gen.go — static REST-path -> gRPC-FQN routing table for
// the api-gateway per-RPC authz middleware.
//
// Source of truth: ` + "`google.api.http`" + ` annotations on every service RPC proto.
// Regenerate with the route extractor after any proto HTTP-rule change.
//
// The middleware needs this to translate an incoming REST request
// (` + "`POST /iam/v1/accounts`" + `) into the canonical gRPC FQN
// (` + "`kacho.cloud.iam.v1.AccountService/Create`" + `) so it can look the method up
// in the embedded permission catalog. Without it, REST requests never match
// catalog keys and every authenticated REST call is denied.
package middleware

// restRoute — one (httpMethod, pathTemplate) -> FQN mapping. pathTemplate is
// the grpc-gateway path with ` + "`{field}`" + ` placeholders and optional ` + "`:verb`" + `
// suffix-action segment.
type restRoute struct {
	Method   string
	Template string
	FQN      string
}

// generatedRestRoutes — full REST<->gRPC route table. Order is
// path-then-method for deterministic, longest-prefix-friendly matching.
var generatedRestRoutes = []restRoute{
`

// render собирает итоговый Go-файл и прогоняет его через go/format, гарантируя
// gofmt-совместимый выход.
func render(routes []Route) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	for _, r := range routes {
		fmt.Fprintf(&buf, "\t{Method: %q, Template: %q, FQN: %q},\n", r.Method, r.Template, r.FQN)
	}
	buf.WriteString("}\n")

	src, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("gofmt generated route table: %w", err)
	}
	return src, nil
}
