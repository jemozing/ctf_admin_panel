package protocols

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

var bindingID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var bindingDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Descriptor struct {
	info    DescriptorInfo
	methods map[string]protoreflect.MethodDescriptor
	types   *protoregistry.Types
}

func validBinding(b Binding) bool {
	return bindingID.MatchString(b.ServiceID) && (b.ReleaseID != "" || b.SourceDigest != "") && (b.ReleaseID == "" || bindingID.MatchString(b.ReleaseID)) && (b.SourceDigest == "" || bindingDigest.MatchString(b.SourceDigest))
}

// NewDescriptor validates a self-contained FileDescriptorSet. Import resolution
// uses only that set; there is no global registry, disk import or server RPC.
func NewDescriptor(raw []byte, binding Binding) (*Descriptor, error) {
	if len(raw) == 0 || len(raw) > MaxDescriptorBytes || !validBinding(binding) {
		return nil, errors.New("descriptor requires bounded bytes and explicit service/release or source binding")
	}
	wireNodes := 20000
	if !descriptorWireBudget(raw, (&descriptorpb.FileDescriptorSet{}).ProtoReflect().Descriptor(), 0, &wireNodes) {
		return nil, errors.New("descriptor wire/object budget exceeded")
	}
	set := new(descriptorpb.FileDescriptorSet)
	if (proto.UnmarshalOptions{RecursionLimit: 64, DiscardUnknown: true, Resolver: new(protoregistry.Types)}).Unmarshal(raw, set) != nil || len(set.File) == 0 || len(set.File) > 64 {
		return nil, errors.New("invalid or oversized descriptor set")
	}
	messages, fields, methods, values := 0, 0, 0, 0
	var checkMessage func(*descriptorpb.DescriptorProto, int) bool
	checkMessage = func(m *descriptorpb.DescriptorProto, depth int) bool {
		if depth > 32 || len(m.GetName()) > 128 {
			return false
		}
		messages++
		fields += len(m.Field)
		if messages > 1024 || fields > 8192 {
			return false
		}
		for _, f := range m.Field {
			if len(f.GetName()) > 128 || len(f.GetJsonName()) > 128 {
				return false
			}
		}
		for _, e := range m.EnumType {
			values += len(e.Value)
			if values > 8192 {
				return false
			}
		}
		for _, nested := range m.NestedType {
			if !checkMessage(nested, depth+1) {
				return false
			}
		}
		return true
	}
	for _, file := range set.File {
		if file.GetName() == "" || len(file.GetName()) > 512 || strings.ContainsAny(file.GetName(), "\x00\r\n") || len(file.GetPackage()) > 512 {
			return nil, errors.New("invalid descriptor names")
		}
		for _, m := range file.MessageType {
			if !checkMessage(m, 0) {
				return nil, errors.New("descriptor type budget exceeded")
			}
		}
		for _, e := range file.EnumType {
			values += len(e.Value)
			if values > 8192 {
				return nil, errors.New("descriptor enum budget exceeded")
			}
		}
		for _, s := range file.Service {
			methods += len(s.Method)
			if methods > 256 || len(s.GetName()) > 128 {
				return nil, errors.New("descriptor method budget exceeded")
			}
		}
	}
	registry, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, errors.New("descriptor imports or declarations are invalid; include dependencies explicitly")
	}
	sum := sha256.Sum256(raw)
	d := &Descriptor{info: DescriptorInfo{Digest: "sha256:" + hex.EncodeToString(sum[:]), Binding: binding, Bytes: len(raw), Files: len(set.File), Methods: []MethodInfo{}}, methods: map[string]protoreflect.MethodDescriptor{}, types: new(protoregistry.Types)}
	var registerMessages func(protoreflect.MessageDescriptors) error
	registerMessages = func(list protoreflect.MessageDescriptors) error {
		for i := 0; i < list.Len(); i++ {
			m := list.Get(i)
			if err := d.types.RegisterMessage(dynamicpb.NewMessageType(m)); err != nil {
				return err
			}
			if err := registerMessages(m.Messages()); err != nil {
				return err
			}
		}
		return nil
	}
	registry.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if err = registerMessages(file.Messages()); err != nil {
			return false
		}
		services := file.Services()
		for i := 0; i < services.Len(); i++ {
			s := services.Get(i)
			for j := 0; j < s.Methods().Len(); j++ {
				m := s.Methods().Get(j)
				path := "/" + string(s.FullName()) + "/" + string(m.Name())
				d.methods[path] = m
				d.info.Methods = append(d.info.Methods, MethodInfo{Path: path, InputType: string(m.Input().FullName()), OutputType: string(m.Output().FullName()), ClientStreaming: m.IsStreamingClient(), ServerStreaming: m.IsStreamingServer()})
			}
		}
		return true
	})
	if err != nil {
		return nil, errors.New("descriptor contains duplicate message declarations")
	}
	sort.Slice(d.info.Methods, func(i, j int) bool { return d.info.Methods[i].Path < d.info.Methods[j].Path })
	return d, nil
}
func (d *Descriptor) Info() DescriptorInfo {
	if d == nil {
		return DescriptorInfo{Methods: []MethodInfo{}}
	}
	out := d.info
	out.Methods = append([]MethodInfo{}, d.info.Methods...)
	return out
}
func (d *Descriptor) matches(binding Binding) bool {
	return d != nil && validBinding(binding) && d.info.Binding.ServiceID == binding.ServiceID && (d.info.Binding.ReleaseID == "" || d.info.Binding.ReleaseID == binding.ReleaseID) && (d.info.Binding.SourceDigest == "" || d.info.Binding.SourceDigest == binding.SourceDigest)
}
func (d *Descriptor) method(path string) protoreflect.MethodDescriptor {
	if d == nil {
		return nil
	}
	return d.methods[path]
}

// Any values are intentionally left opaque. A self-referential Any payload can
// otherwise bypass normal message recursion/allocation limits while protojson
// recursively expands its embedded bytes. This resolver never fetches types.
type noAnyResolver struct{ *protoregistry.Types }

func (r noAnyResolver) FindMessageByURL(string) (protoreflect.MessageType, error) {
	return nil, protoregistry.NotFound
}

func (d *Descriptor) decode(data []byte, path string, response bool, binding Binding) (string, json.RawMessage, string) {
	if !d.matches(binding) {
		return "", nil, "descriptor_binding_mismatch"
	}
	method := d.method(path)
	if method == nil {
		return "", nil, "descriptor_method_not_found"
	}
	md := method.Input()
	if response {
		md = method.Output()
	}
	budget := 10000
	if !checkWire(data, md, 0, &budget) {
		return string(md.FullName()), nil, "protobuf_wire_or_resource_limit"
	}
	msg := dynamicpb.NewMessage(md)
	if (proto.UnmarshalOptions{RecursionLimit: 32, Resolver: d.types}).Unmarshal(data, msg) != nil {
		return string(md.FullName()), nil, "protobuf_decode_failed"
	}
	jsonNodes, jsonBytes := 10000, MaxMessageBytes
	if !estimateJSON(msg.ProtoReflect(), 0, &jsonNodes, &jsonBytes) {
		return string(md.FullName()), nil, "protobuf_json_resource_limit_or_opaque_any"
	}
	decoded, err := (protojson.MarshalOptions{Resolver: noAnyResolver{d.types}, UseProtoNames: false}).Marshal(msg)
	if err != nil {
		return string(md.FullName()), nil, "protobuf_json_failed"
	}
	if len(decoded) > MaxMessageBytes {
		return string(md.FullName()), nil, "protobuf_json_limit"
	}
	return string(md.FullName()), json.RawMessage(decoded), ""
}

// This bounds object/field allocation before dynamicpb materializes an
// untrusted message, including packed repeated values and nested messages.
func checkWire(data []byte, md protoreflect.MessageDescriptor, depth int, budget *int) bool {
	if depth > 24 || len(data) > MaxMessageBytes {
		return false
	}
	for len(data) > 0 {
		*budget--
		if *budget < 0 {
			return false
		}
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 || number < 1 || kind == protowire.StartGroupType || kind == protowire.EndGroupType {
			return false
		}
		data = data[n:]
		length := protowire.ConsumeFieldValue(number, kind, data)
		if length < 0 {
			return false
		}
		field := md.Fields().ByNumber(protoreflect.FieldNumber(number))
		if kind == protowire.BytesType && field != nil {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return false
			}
			if field.Kind() == protoreflect.MessageKind {
				if !checkWire(value, field.Message(), depth+1, budget) {
					return false
				}
			} else if field.IsPacked() {
				*budget -= len(value)
				if *budget < 0 {
					return false
				}
			}
		}
		data = data[length:]
	}
	return true
}

// Conservatively bound JSON construction before protojson allocates output.
// Escaped strings and names can expand sixfold; byte strings become base64.
func estimateJSON(msg protoreflect.Message, depth int, nodes, left *int) bool {
	if depth > 24 || !msg.IsValid() {
		return false
	}
	if msg.Descriptor().FullName() == "google.protobuf.Any" {
		return false
	}
	*nodes--
	*left -= 2
	if *nodes < 0 || *left < 0 {
		return false
	}
	valid := true
	var value func(protoreflect.FieldDescriptor, protoreflect.Value) bool
	value = func(field protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		*nodes--
		if *nodes < 0 {
			return false
		}
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			return estimateJSON(v.Message(), depth+1, nodes, left)
		case protoreflect.StringKind:
			*left -= len(v.String())*6 + 2
		case protoreflect.BytesKind:
			*left -= len(v.Bytes())*2 + 4
		case protoreflect.EnumKind:
			if e := field.Enum().Values().ByNumber(v.Enum()); e != nil {
				*left -= len(e.Name())*6 + 2
			} else {
				*left -= 32
			}
		default:
			*left -= 32
		}
		return *left >= 0
	}
	msg.Range(func(field protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		*left -= len(field.JSONName())*6 + 4
		if *left < 0 {
			valid = false
			return false
		}
		if field.IsList() {
			list := v.List()
			*left -= 2
			for i := 0; i < list.Len(); i++ {
				*left--
				if !value(field, list.Get(i)) {
					valid = false
					return false
				}
			}
		} else if field.IsMap() {
			*left -= 2
			v.Map().Range(func(key protoreflect.MapKey, item protoreflect.Value) bool {
				*left -= len(key.String())*6 + 4
				if !value(field.MapValue(), item) {
					valid = false
					return false
				}
				return true
			})
		} else if !value(field, v) {
			valid = false
			return false
		}
		return valid
	})
	return valid && *left >= 0
}

// Descriptor protobufs contain many known repeated message fields (including
// SourceCodeInfo and custom option scaffolding). Count them before Unmarshal
// allocates one Go object per tiny encoded record. Strings remain opaque; only
// fields known by descriptor.proto to be messages recurse.
func descriptorWireBudget(data []byte, md protoreflect.MessageDescriptor, depth int, nodes *int) bool {
	if depth > 48 || len(data) > MaxDescriptorBytes {
		return false
	}
	for len(data) > 0 {
		*nodes--
		if *nodes < 0 {
			return false
		}
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 || number < 1 || kind == protowire.StartGroupType || kind == protowire.EndGroupType {
			return false
		}
		data = data[n:]
		length := protowire.ConsumeFieldValue(number, kind, data)
		if length < 0 {
			return false
		}
		field := md.Fields().ByNumber(protoreflect.FieldNumber(number))
		if kind == protowire.BytesType && field != nil {
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return false
			}
			if field.Kind() == protoreflect.MessageKind {
				if !descriptorWireBudget(value, field.Message(), depth+1, nodes) {
					return false
				}
			} else if field.IsPacked() {
				*nodes -= len(value)
				if *nodes < 0 {
					return false
				}
			}
		}
		data = data[length:]
	}
	return true
}
