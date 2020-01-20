#include <cassert>
#include <cstring>
#include <exception>
#include <iostream>

extern "C" {
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/version.h>

// from stdint
#include <uint16.h>
#include <uint32.h>
#include <uint64.h>
#include <uint8.h>
}

#include "error.h"
#include "loadimage.h"
#include "sleigh.h"
#include "sleigh_stubs.h"
#include "translate.h"
#include "varnodedata.h"

#define Val_none Val_int(0)
#define Some_val(v) Field(v, 0)
#define Val_emptyarray Atom(0)

static CAMLprim value Val_some(value v) {
  CAMLparam1(v);
  CAMLlocal1(some);
  some = caml_alloc(1, 0);
  Store_field(some, 0, v);
  CAMLreturn(some);
}

#define Sleigh_handle_val(v)                                                   \
  (*reinterpret_cast<SleighDisasm **>(Data_custom_val(v)))

void BytesLoader::loadFill(uint1 *ptr, int4 size, const Address &addr) {
  uintb start = addr.getOffset();
  uintb max = base_addr + (length - 1);

  for (int4 i = 0; i < size; ++i) {
    uintb curr_off = start + i;
    if ((curr_off < base_addr) || (curr_off > max)) {
      ptr[i] = 0;
    } else {
      uintb diff = curr_off - base_addr;
      ptr[i] = data[static_cast<int4>(diff)];
    }
  }
}

static void ml_sleigh_finalise_handle(value h) {
  CAMLparam1(h);
  delete Sleigh_handle_val(h);
  CAMLreturn0;
}

static struct custom_operations ml_sleigh_handle_custom_ops = {
    (char *)"ml_sleigh_handle_custom_ops",
    ml_sleigh_finalise_handle,
    custom_compare_default,
    custom_compare_ext_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default,
#if OCAML_VERSION_MAJOR >= 4 && OCAML_VERSION_MINOR >= 8
    nullptr, // custom_fixed_length
#endif
};

static value ml_sleigh_alloc_handle(SleighDisasm *handle) {
  CAMLparam0();
  CAMLlocal1(h);
  h = caml_alloc_custom(&ml_sleigh_handle_custom_ops, sizeof(SleighDisasm *), 0,
                        1);
  memcpy(Data_custom_val(h), &handle, sizeof(SleighDisasm *));
  CAMLreturn(h);
}

CAMLprim value ml_sleigh_create(value sla, value base_addr, value bytes) {
  CAMLparam3(sla, base_addr, bytes);
  try {
    auto *loader = new BytesLoader(Uint64_val(base_addr), Bytes_val(bytes),
                                   caml_string_length(bytes));
    auto *context = new ContextInternal();
    auto *sleigh = new Sleigh(loader, context);

    DocumentStorage doc_storage;
    auto *root = doc_storage.openDocument(String_val(sla))->getRoot();
    doc_storage.registerTag(root);

    sleigh->initialize(doc_storage);

    CAMLreturn(
        ml_sleigh_alloc_handle(new SleighDisasm(sleigh, context, loader)));
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (XmlError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_assembly(value t, value addr) {
  CAMLparam2(t, addr);
  CAMLlocal1(v);
  try {
    AssemblyRaw emit;
    Address address(Sleigh_handle_val(t)->sleigh->getDefaultSpace(),
                    Uint64_val(addr));

    if (address.isInvalid()) {
      caml_raise_with_string(*caml_named_value("Sleigh_error"),
                             "invalid address");
    }

    auto len = Sleigh_handle_val(t)->sleigh->printAssembly(emit, address);
    if (len > 0) {
      v = caml_alloc(3, 0);
      Store_field(v, 0, caml_copy_string(emit.mnemonic.c_str()));
      Store_field(v, 1, caml_copy_string(emit.operands.c_str()));
      Store_field(v, 2, Val_int(len));
      CAMLreturn(v);
    }

    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           "disassembly failed");

  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

static value ml_sleigh_vnd_to_opnd(VarnodeData *vnd) {
  CAMLparam0();
  CAMLlocal1(v);

  switch (vnd->space->getType()) {
  case IPTR_CONSTANT: { // constant
    v = caml_alloc(2, 1);
    Store_field(v, 0, copy_uint64(vnd->offset));
    Store_field(v, 1, Val_int(vnd->size));
    break;
  }
  case IPTR_PROCESSOR: {
    auto trans = vnd->space->getTrans();
    auto reg = trans->getRegisterName(vnd->space, vnd->offset, vnd->size);
    if (reg.empty()) { // address
      v = caml_alloc(2, 0);
      Store_field(v, 0, copy_uint64(vnd->offset));
      Store_field(v, 1, Val_int(vnd->size));
    } else { // register
      v = caml_alloc(3, 2);
      Store_field(v, 0, caml_copy_string(reg.c_str()));
      Store_field(v, 1, copy_uint64(vnd->offset));
      Store_field(v, 2, Val_int(vnd->size));
    }
    break;
  }
  case IPTR_INTERNAL: // variable
  default: {
    v = caml_alloc(3, 3);
    auto space = vnd->space->getName();
    Store_field(v, 0, caml_copy_string(space.c_str()));
    Store_field(v, 1, copy_uint64(vnd->offset));
    Store_field(v, 2, Val_int(vnd->size));
    break;
  }
  }

  CAMLreturn(v);
}

void PcodeRawOut::dump(const Address &_addr, OpCode opc, VarnodeData *outvar,
                       VarnodeData *vars, int4 isize) {
  CAMLparam0();
  CAMLlocal4(p, insn, op, args);

  p = caml_alloc(2, 0);

#define OP_START (10)
#define UNOP(N, V)                                                             \
  case N: {                                                                    \
    assert(isize == 1);                                                        \
    insn = caml_alloc(2, OP_START + V);                                        \
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(outvar));                       \
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[0]));                     \
    break;                                                                     \
  }
#define BINOP(N, V)                                                            \
  case N: {                                                                    \
    assert(isize == 2);                                                        \
    insn = caml_alloc(3, OP_START + V);                                        \
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(outvar));                       \
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[0]));                     \
    Store_field(insn, 2, ml_sleigh_vnd_to_opnd(&vars[1]));                     \
    break;                                                                     \
  }

  switch (opc) {
  case CPUI_COPY: { // Copy (dst, src)
    assert(isize == 1);
    insn = caml_alloc(2, 0);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(outvar));
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
  case CPUI_LOAD: {
    assert(isize == 2);
    insn = caml_alloc(2, 1);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(outvar));
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[1]));
    break;
  }
  case CPUI_STORE: {
    assert(isize == 3);
    insn = caml_alloc(2, 2);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[1]));
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[2]));
    break;
  }
  case CPUI_BRANCH: {
    assert(isize == 1);
    insn = caml_alloc(1, 3);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
  case CPUI_CBRANCH: {
    assert(isize == 3);
    insn = caml_alloc(2, 4);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[1]));
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[2]));
    break;
  }
  case CPUI_CALL: {
    assert(isize == 1);
    insn = caml_alloc(1, 5);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
  case CPUI_CALLIND: {
    assert(isize == 1);
    insn = caml_alloc(1, 6);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
  case CPUI_CALLOTHER: {
    assert(isize >= 1);
    insn = caml_alloc(3, 7);
    if (isize == 1) {
      args = Val_emptyarray;
    } else {
      args = caml_alloc(isize-1, 0);
      for (size_t i = 1; i < isize; i++) {
        Store_field(args, i-1, ml_sleigh_vnd_to_opnd(&vars[i]));
      }
    }
    Store_field(insn, 0, outvar ? Val_some(ml_sleigh_vnd_to_opnd(outvar)) : Val_none);
    Store_field(insn, 1, ml_sleigh_vnd_to_opnd(&vars[0]));
    Store_field(insn, 2, args);
    break;
  }
  case CPUI_BRANCHIND: {
    assert(isize == 1);
    insn = caml_alloc(1, 8);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
  case CPUI_RETURN: {
    assert(isize == 1);
    insn = caml_alloc(1, 9);
    Store_field(insn, 0, ml_sleigh_vnd_to_opnd(&vars[0]));
    break;
  }
    UNOP(CPUI_INT_ZEXT, 0)
    UNOP(CPUI_INT_SEXT, 1)
    BINOP(CPUI_INT_CARRY, 2)
    BINOP(CPUI_INT_SCARRY, 3)
    BINOP(CPUI_INT_SBORROW, 4)
    UNOP(CPUI_INT_2COMP, 5)
    UNOP(CPUI_INT_NEGATE, 6)
    BINOP(CPUI_INT_EQUAL, 7)
    BINOP(CPUI_INT_NOTEQUAL, 8)
    BINOP(CPUI_INT_SLESS, 9)
    BINOP(CPUI_INT_SLESSEQUAL, 10)
    BINOP(CPUI_INT_LESS, 11)
    BINOP(CPUI_INT_LESSEQUAL, 12)
    BINOP(CPUI_INT_ADD, 13)
    BINOP(CPUI_INT_SUB, 14)
    BINOP(CPUI_INT_MULT, 15)
    BINOP(CPUI_INT_DIV, 16)
    BINOP(CPUI_INT_SDIV, 17)
    BINOP(CPUI_INT_REM, 18)
    BINOP(CPUI_INT_SREM, 19)
    BINOP(CPUI_INT_XOR, 20)
    BINOP(CPUI_INT_OR, 21)
    BINOP(CPUI_INT_AND, 22)
    BINOP(CPUI_INT_LEFT, 23)
    BINOP(CPUI_INT_RIGHT, 24)
    BINOP(CPUI_INT_SRIGHT, 25)
    UNOP(CPUI_BOOL_NEGATE, 26)
    BINOP(CPUI_BOOL_XOR, 27)
    BINOP(CPUI_BOOL_OR, 28)
    BINOP(CPUI_BOOL_AND, 29)
    UNOP(CPUI_FLOAT_NAN, 30)
    UNOP(CPUI_FLOAT_NEG, 31)
    UNOP(CPUI_FLOAT_ABS, 32)
    UNOP(CPUI_FLOAT_SQRT, 33)
    UNOP(CPUI_FLOAT_INT2FLOAT, 34)
    UNOP(CPUI_FLOAT_FLOAT2FLOAT, 35)
    UNOP(CPUI_FLOAT_TRUNC, 36)
    UNOP(CPUI_FLOAT_CEIL, 37)
    UNOP(CPUI_FLOAT_FLOOR, 38)
    UNOP(CPUI_FLOAT_ROUND, 39)
    BINOP(CPUI_FLOAT_ADD, 40)
    BINOP(CPUI_FLOAT_SUB, 41)
    BINOP(CPUI_FLOAT_MULT, 42)
    BINOP(CPUI_FLOAT_DIV, 43)
  default: {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           "unhandled pcode operation");
  }
  }

#undef UNOP
#undef BINOP
#undef OP_START

  Store_field(p, 0, insn);
  Store_field(p, 1, Val_emptylist);

  if (insns == Val_emptylist) {
    insns = p;
  } else {
    Store_field(last, 1, p);
  }

  last = p;

  CAMLreturn0;
}

CAMLprim value ml_sleigh_pcode(value t, value address) {
  CAMLparam2(t, address);
  CAMLlocal1(v);
  try {
    int4 length;

    Address addr(Sleigh_handle_val(t)->sleigh->getDefaultSpace(),
                 Uint64_val(address));

    if (addr.isInvalid()) {
      caml_raise_with_string(*caml_named_value("Sleigh_error"),
                             "invalid address");
    }

    PcodeRawOut emit;
    length = Sleigh_handle_val(t)->sleigh->oneInstruction(emit, addr);

    if (length > 0) {
      v = caml_alloc(2, 0);
      Store_field(v, 0, emit.insns);
      Store_field(v, 1, Val_int(length));
      CAMLreturn(v);
    } else {
      caml_raise_with_string(*caml_named_value("Sleigh_error"),
                             "disassembly to pcode failed");
    }
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_registers(value t) {
  CAMLparam1(t);
  CAMLlocal3(v, x, xs);

  try {
    std::map<VarnodeData, std::string> regs;
    Sleigh_handle_val(t)->sleigh->getAllRegisters(regs);

    xs = Val_emptylist;

    for (auto [k, r] : regs) {
      auto name = k.space->getName();

      x = caml_alloc(3, 0);
      Store_field(x, 0, caml_copy_string(name.c_str()));
      Store_field(x, 1, copy_uint64(k.offset));
      Store_field(x, 2, Val_int(k.size));

      v = caml_alloc(2, 0);
      Store_field(v, 0, caml_copy_string(r.c_str()));
      Store_field(v, 1, x);

      x = caml_alloc(2, 0);
      Store_field(x, 0, v);
      Store_field(x, 1, xs);

      xs = x;
    }

    CAMLreturn(xs);
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_user_ops(value t) {
  CAMLparam1(t);
  CAMLlocal1(xs);

  xs = Val_emptyarray;

  std::vector<std::string> uops;
  try {
    Sleigh_handle_val(t)->sleigh->getUserOpNames(uops);
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }

  if (std::size(uops) > 0) {
    xs = caml_alloc(std::size(uops), 0);
    for (auto i = 0; i < std::size(uops); ++i) {
      Store_field(xs, i, caml_copy_string(uops[i].c_str()));
    }
  }

  CAMLreturn(xs);
}

CAMLprim value ml_sleigh_endian(value t) {
  CAMLparam1(t);
  try {
    if (Sleigh_handle_val(t)->sleigh->isBigEndian()) {
      CAMLreturn(Val_int(0));
    } else {
      CAMLreturn(Val_int(1));
    }
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_alignment(value t) {
  CAMLparam1(t);
  try {
    CAMLreturn(Val_int(Sleigh_handle_val(t)->sleigh->getAlignment()));
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_mutable_context(value t, value v) {
  CAMLparam2(t, v);
  try {
    Sleigh_handle_val(t)->sleigh->allowContextSet(Bool_val(v));
    CAMLreturn(Val_unit);
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}

CAMLprim value ml_sleigh_set_context_variable(value t, value var, value val) {
  CAMLparam3(t, var, val);
  try {
    Sleigh_handle_val(t)->sleigh->setContextDefault(String_val(var),
                                                    Uint64_val(val));
    CAMLreturn(Val_unit);
  } catch (LowlevelError &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"),
                           e.explain.c_str());
  } catch (std::exception &e) {
    caml_raise_with_string(*caml_named_value("Sleigh_error"), e.what());
  }
}
