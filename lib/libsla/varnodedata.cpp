#include "translate.h"
#include "varnodedata.h"

/// Build this VarnodeData from an \b \<addr\> tag
/// \param el is the parsed tag
/// \param manage is the address space manager
void VarnodeData::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  space = (AddrSpace *)0;
  size = 0;
  int4 num = el->getNumAttributes();
  for(int4 i=0;i<num;++i) {
    if (el->getAttributeName(i)=="space") {
      space = manage->getSpaceByName(el->getAttributeValue(i));
      if (space == (AddrSpace *)0)
	throw LowlevelError("Unknown space name: "+el->getAttributeValue(i));
      offset = space->restoreXmlAttributes(el,size);
      return;
    }
    else if (el->getAttributeName(i)=="name") {
      const Translate *trans = manage->getDefaultSpace()->getTrans();
      const VarnodeData &point(trans->getRegister(el->getAttributeValue(i)));
      *this = point;
      return;
    }
  }
}

