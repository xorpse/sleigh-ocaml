open Stdint

type t

exception Sleigh_error of string
let () = Callback.register_exception "Sleigh_error" (Sleigh_error "this_value_is_never_used")

type varnode = {
  space  : string;
  offset : uint64;
  size   : int;
}
type register = varnode
type constant = {
  value : uint64;
  size  : int;
}
type address = uint64

type operand = Address of { value : uint64; size : int }
             | Constant of { value : uint64; size : int }
             | Register of { name : string; offset : uint64; size : int }
             | Variable of { space : string; offset : uint64; size : int }

type insn = {
  mnemonic : string;
  operands : string;
  size     : int;
}

type pcode = Copy of { dst : operand; src : operand }
           | Load of { dst : operand; src : operand }
           | Store of { dst : operand; src : operand }
           | Branch of { tgt : operand }
           | CBranch of { tgt: operand; cond : operand }
           | Call of { tgt : operand }
           | CallInd of { tgt : operand }
           | CallOther of { dst : operand option; tgt : operand; args : operand array }
           | BranchInd of { tgt : operand }
           | Return of { dst : operand }
           | IZExt of { dst : operand; arg : operand }
           | ISExt of { dst : operand; arg : operand }
           | ICarry of { dst : operand; arg1 : operand; arg2 : operand }
           | ISCarry of { dst : operand; arg1 : operand; arg2 : operand }
           | ISBorrow of { dst : operand; arg1 : operand; arg2 : operand }
           | I2Comp of { dst : operand; arg : operand }
           | INeg of { dst : operand; arg : operand }
           | IEqual of { dst : operand; arg1 : operand; arg2 : operand }
           | INotEqual of { dst : operand; arg1 : operand; arg2 : operand }
           | ISLess of { dst : operand; arg1 : operand; arg2 : operand }
           | ISLessEqual of { dst : operand; arg1 : operand; arg2 : operand }
           | ILess of { dst : operand; arg1 : operand; arg2 : operand }
           | ILessEqual of { dst : operand; arg1 : operand; arg2 : operand }
           | IAdd of { dst : operand; arg1 : operand; arg2 : operand }
           | ISub of { dst : operand; arg1 : operand; arg2 : operand }
           | IMult of { dst : operand; arg1 : operand; arg2 : operand }
           | IDiv of { dst : operand; arg1 : operand; arg2 : operand }
           | ISDiv of { dst : operand; arg1 : operand; arg2 : operand }
           | IRem of { dst : operand; arg1 : operand; arg2 : operand }
           | ISRem of { dst : operand; arg1 : operand; arg2 : operand }
           | IXor of { dst : operand; arg1 : operand; arg2 : operand }
           | IOr of { dst : operand; arg1 : operand; arg2 : operand }
           | IAnd of { dst : operand; arg1 : operand; arg2 : operand }
           | ILeft of { dst : operand; arg1 : operand; arg2 : operand }
           | IRight of { dst : operand; arg1 : operand; arg2 : operand }
           | ISRight of { dst : operand; arg1 : operand; arg2 : operand }
           | BNeg of { dst : operand; arg : operand }
           | BXor of { dst : operand; arg1 : operand; arg2 : operand }
           | BOr of { dst : operand; arg1 : operand; arg2 : operand }
           | BAnd of { dst : operand; arg1 : operand; arg2 : operand }
           | FNaN of { dst : operand; arg : operand }
           | FNeg of { dst : operand; arg : operand }
           | FAbs of { dst : operand; arg : operand }
           | FSqrt of { dst : operand; arg : operand }
           | FIntToFloat of { dst : operand; arg : operand }
           | FFloatToFloat of { dst : operand; arg : operand }
           | FTrunc of { dst : operand; arg : operand }
           | FCeil of { dst : operand; arg : operand }
           | FFloor of { dst : operand; arg : operand }
           | FRound of { dst : operand; arg : operand }
           | FAdd of { dst : operand; arg1 : operand; arg2 : operand }
           | FSub of { dst : operand; arg1 : operand; arg2 : operand }
           | FMult of { dst : operand; arg1 : operand; arg2 : operand }
           | FDiv of { dst : operand; arg1 : operand; arg2 : operand }
type pinsn = {
  opcodes : pcode list;
  size    : int;
}

type endian = Big | Little
type arch = string

external create_ffi : string -> uint64 -> bytes -> t = "ml_sleigh_create"

external set_mutable  : t -> bool -> unit = "ml_sleigh_mutable_context"
external set_variable : t -> string -> uint64 -> unit = "ml_sleigh_set_context_variable"

external alignment : t -> int = "ml_sleigh_alignment"
external endian    : t -> endian = "ml_sleigh_endian"

external assembly  : t -> address:uint64 -> insn = "ml_sleigh_assembly"
external pcode     : t -> address:uint64 -> pinsn = "ml_sleigh_pcode"

external registers : t -> (string * register) list = "ml_sleigh_registers"
external user_ops  : t -> string array = "ml_sleigh_user_ops"

let create ?(immutable = true) ~arch ~base bytes =
  let t = create_ffi arch base bytes in
  set_mutable t (not immutable);
  t
