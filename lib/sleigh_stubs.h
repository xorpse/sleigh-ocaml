#include <algorithm>
#include <iostream>
#include <memory>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/version.h>

#include "loadimage.h"
#include "sleigh.h"
#include "types.h"
#include "varnodedata.h"

class BytesLoader : public LoadImage {
private:
  uintb base_addr;
  int4 length;
  std::unique_ptr<uint1[]> data;

public:
  BytesLoader(uintb addr, const uint1 *bytes, int4 len)
    : LoadImage("<memory>")
    , base_addr{addr}
    , length{len}
    , data{std::make_unique<uint1[]>(length)} {
    std::copy(bytes, bytes+len, data.get());
  }

  virtual void loadFill(uint1 *ptr, int4 size, const Address &addr);
  virtual std::string getArchType(void) const { return "<BytesLoader>"; }
  virtual void adjustVma(long _adjust) { }
};

class AssemblyRaw : public AssemblyEmit {
public:
  std::string mnemonic;
  std::string operands;

  virtual void dump(const Address &_addr,const std::string &mnem,const std::string &body) {
    mnemonic = mnem;
    operands = body;
  }
};

class PcodeRawOut : public PcodeEmit {
public:
  value insns;
  value last;

  PcodeRawOut() : insns{Val_emptylist}, last{Val_emptylist} {
    caml_register_global_root(&(this->insns));
    caml_register_global_root(&(this->last));
  }
  ~PcodeRawOut() {
    caml_remove_global_root(&(this->last));
    caml_remove_global_root(&(this->insns));
  }
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
};

class SleighDisasm {
public:
  std::unique_ptr<Sleigh> sleigh;
  std::unique_ptr<ContextInternal> context;
  std::unique_ptr<BytesLoader> loader;

  SleighDisasm(Sleigh *sleigh, ContextInternal *context, BytesLoader *loader)
    : sleigh{std::move(sleigh)}, context{std::move(context)}, loader{std::move(loader)} {}
};

extern "C" {
  CAMLextern value ml_sleigh_create(value sla, value base_addr, value bytes);
  CAMLextern value ml_sleigh_assembly(value t, value addr);
  CAMLextern value ml_sleigh_pcode(value t, value addr);
  CAMLextern value ml_sleigh_registers(value t);
  CAMLextern value ml_sleigh_user_ops(value t);
  CAMLextern value ml_sleigh_endian(value t);
  CAMLextern value ml_sleigh_alignment(value t);
  CAMLextern value ml_sleigh_mutable_context(value t, value v);
  CAMLextern value ml_sleigh_set_context_variable(value t, value var, value val);
}
