#ifndef __CPUI_VARNODEDATA__
#define __CPUI_VARNODEDATA__

#include "address.h"

/// \brief Data defining a specific memory location
///
/// Within the decompiler's model of a processor, any register,
/// memory location, or other variable can always be represented
/// as an address space, an offset within the space, and the
/// size of the sequence of bytes.  This is more commonly referred
/// to as a Varnode, but this is a bare-bones container
/// for the data that doesn't have the cached attributes and
/// the dataflow links of the Varnode within its syntax tree.
struct VarnodeData {
  AddrSpace *space;		///< The address space
  uintb offset;			///< The offset within the space
  uint4 size;                   ///< The number of bytes in the location
  bool operator<(const VarnodeData &op2) const;  ///< An ordering for VarnodeData
  bool operator==(const VarnodeData &op2) const; ///< Compare for equality
  bool operator!=(const VarnodeData &op2) const; ///< Compare for inequality

  /// Get the location of the varnode as an address
  Address getAddr(void) const;

  /// Recover this object from an XML tag
  void restoreXml(const Element *el,const AddrSpaceManager *manage);
};

/// VarnodeData can be sorted in terms of the space its in
/// (the space's \e index), the offset within the space,
/// and finally by the size.
/// \param op2 is the object being compared to
/// \return true if \e this is less than \e op2
inline bool VarnodeData::operator<(const VarnodeData &op2) const {
  if (space != op2.space) return (space->getIndex() < op2.space->getIndex());
  if (offset != op2.offset) return (offset < op2.offset);
  return (size > op2.size);	// BIG sizes come first
}

/// Compare VarnodeData for equality. The space, offset, and size
/// must all be exactly equal
/// \param op2 is the object being compared to
/// \return true if \e this is equal to \e op2
inline bool VarnodeData::operator==(const VarnodeData &op2) const {
  if (space != op2.space) return false;
  if (offset != op2.offset) return false;
  return (size == op2.size);
}

/// Compare VarnodeData for inequality. If either the space,
/// offset, or size is not equal, return \b true.
/// \param op2 is the object being compared to
/// \return true if \e this is not equal to \e op2
inline bool VarnodeData::operator!=(const VarnodeData &op2) const {
  if (space != op2.space) return true;
  if (offset != op2.offset) return true;
  return (size != op2.size);
}

/// This is a convenience function to construct a full Address from the
/// VarnodeData's address space and offset
/// \return the address of the varnode
inline Address VarnodeData::getAddr(void) const {
  return Address(space,offset);
}

#endif
