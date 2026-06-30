#ifndef PACKET_TADO_H
#define PACKET_TADO_H

#include <epan/packet.h>

extern dissector_handle_t tado_handle;

void proto_register_tado(void);
void proto_reg_handoff_tado(void);

#endif /* PACKET_TADO_H */
