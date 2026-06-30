/*
* packet-tirpi.c
*
* TI Radio Packet Info Dissector
* By Bjorn Selvig <b.selvig@ti.com>
* Copyright 2017 Texas Instruments
* 
* This file is based on packet-PROTOABBREV.c downloaded from:
* https://github.com/boundary/wireshark/blob/master/doc/packet-PROTOABBREV.c
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tvbuff.h>

/*
* This dissector is for the TI Radio Packet Info header which includes meta information about the received packet, 
* and is meant to be used with the TiWsPc2 packet sniffer software from Texas Instruments. 
*
* The format of the header is shown below. 
*
* The variable length payload is forwarded to next dissector depending on the Protocol field
* value. 
* Currently the following protocols are supported:
* - Generic (raw data format)
* - IEEE 802.15.4g
* - IEEE 802.15.4
* - BLE
* - WBMS
*  ----------------------------------------------------------------------------------------------------------------------
*  | Version | Length | Interface Type | Interface ID | Protocol | PHY | Frequency | Channel | RSSI | Status | Payload  |
*  | 1B      | 2B     | 1B             | 2B           | 1B       | 1B  | 4B        | 2B      | 1B   | 1B     | Variable |
*  ----------------------------------------------------------------------------------------------------------------------
*/

/* Dissector Function Prototypes */
static int dissect_ti_rpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
void proto_register_ti_rpi(void);
void proto_reg_handoff_ti_rpi(void);
 

/* Initialize the protocol and registered fields */
static int proto_ti_rpi = -1;
static int hf_ti_rpi_interface = -1;
static int hf_ti_rpi_frequency = -1;
static int hf_ti_rpi_channel = -1;
static int hf_ti_rpi_phy = -1;
static int hf_ti_rpi_rssi = -1;
static int hf_ti_rpi_status = -1;
static int hf_ti_rpi_length = -1;


/* Initialize the subtree pointers */
static gint ett_ti_rpi = -1;


/* UDP port number */
#define TI_RPI_UDP_PORT 17760 


/* Protocol Abbreviations */
#define TI802154GE_PROTOABBREV_TI802154GE         "ti802.15.4ge"
#define TI802154GE_PROTOABBREV_SUNPHY_TI802154GE  "ti802.15.4ge.sunphy"


/* Dissector handles */
static dissector_handle_t ti_rti_handle;
static dissector_handle_t ti802154ge_handle;
static dissector_handle_t ti802154ge_sun_phy_handle;
static dissector_handle_t data_handle;
static dissector_handle_t legacy_ieee802154_handle;
static dissector_handle_t ble_handle;
static dissector_handle_t wbms_handle;
static dissector_handle_t sixlowpan_handle;

extern dissector_handle_t tado_handle;


/* Minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define TI_RPI_MIN_LENGTH               17


/* Interface type values */
#define INTERFACE_TYPE_COM              0
#define INTERFACE_TYPE_CEBAL            1


/* PHY type values */
#define PHY_TYPE_UNUSED                     0
#define PHY_TYPE_50KBPS_GFSK                1
#define PHY_TYPE_SLR                        2
#define PHY_TYPE_OQPSK                      3
#define PHY_TYPE_200KBPS_GFSK               4
#define PHY_TYPE_BLE                        5
#define PHY_TYPE_WBMS                       6
#define PHY_TYPE_50KBPS_GFSK_WISUN_1A       7
#define PHY_TYPE_50KBPS_GFSK_WISUN_1B       8
#define PHY_TYPE_100KBPS_GFSK_WISUN_2A      9
#define PHY_TYPE_100KBPS_GFSK_WISUN_2B      10
#define PHY_TYPE_150KBPS_GFSK_WISUN_3       11
#define PHY_TYPE_200KBPS_GFSK_WISUN_4A      12
#define PHY_TYPE_200KBPS_GFSK_WISUN_4B      13
#define PHY_TYPE_100KBPS_GFSK_ZIGBEE_R23    14
#define PHY_TYPE_500KBPS_GFSK_ZIGBEE_R23    15

#define PHY_50KBPS_GFSK_STRING              "50 Kbps GFSK"
#define PHY_SLR_STRING                      "SLR"
#define PHY_OQPSK_STRING                    "O-QPSK"
#define PHY_200KBPS_GFSK_STRING             "200 Kbps GFSK"
#define PHY_BLE_STRING                      "BLE 1 Mbps"
#define PHY_WBMS_STRING                     "WBMS 2 Mbps"
#define PHY_50KBPS_GFSK_WISUN_1A_STRING     "50 Kbps GFSK (Wi-SUN mode 1a)"
#define PHY_50KBPS_GFSK_WISUN_1B_STRING     "50 Kbps GFSK (Wi-SUN mode 1b)"
#define PHY_100KBPS_GFSK_WISUN_2A_STRING    "100 Kbps GFSK (Wi-SUN mode 2a)"
#define PHY_100KBPS_GFSK_WISUN_2B_STRING    "100 Kbps GFSK (Wi-SUN mode 2b)"
#define PHY_150KBPS_GFSK_WISUN_3_STRING     "150 Kbps GFSK (Wi-SUN mode 3)"
#define PHY_200KBPS_GFSK_WISUN_4A_STRING    "200 Kbps GFSK (Wi-SUN mode 4a)"
#define PHY_200KBPS_GFSK_WISUN_4B_STRING    "200 Kbps GFSK (Wi-SUN mode 4b)"
#define PHY_100KBPS_GFSK_ZIGBEE_R23_STRING  "100 Kbps GFSK (ZigBee R23)"
#define PHY_500KBPS_GFSK_ZIGBEE_R23_STRING  "500 Kbps GFSK (ZigBee R23)"

/* Protocol values */
#define PROTOCOL_GENERIC                0
#define PROTOCOL_IEEE_802_15_4_G        1
#define PROTOCOL_IEEE_802_15_4          2
#define PROTOCOL_BLE                    3
#define PROTOCOL_WBMS                   4

/* Header field offset values */
#define INTERFACE_TYPE_OFFSET           3
#define INTERFACE_ID_OFFSET             4
#define PROTOCOL_OFFSET                 6
#define PHY_OFFSET                      7
#define FREQUENCY_OFFSET                8
#define FRACTIONAL_FREQUENCY_OFFSET     10
#define CHANNEL_OFFSET                  12
#define RSSI_OFFSET                     14
#define STATUS_OFFSET                   15
#define PAYLOAD_OFFSET                  16


/* Header field size values */
#define INTERFACE_ID_SIZE               2
#define PHY_SIZE                        1
#define FREQUENCY_SIZE                  4     /* Size of frequency + fractional frequency values in total */
#define CHANNEL_SIZE                    2
#define RSSI_SIZE                       1
#define STATUS_SIZE                     1


/*FUNCTION:------------------------------------------------------
*  NAME
*      dissect_ti_rpi
*  DESCRIPTION
*      Dissector for TI Radio Packet Info meta header packet 
*
*  PARAMETERS
*      tvbuff_t *tvb       - pointer to buffer containing raw packet.
*      packet_info *pinfo  - pointer to packet information fields
*      proto_tree *tree    - pointer to data tree wireshark uses to display packet.
*  RETURNS
*      number of bytes that were dissected
*---------------------------------------------------------------
*/
static int
dissect_ti_rpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* local variables */
    proto_item *ti;
    proto_tree *ti_rpi_tree;
    guint8 interfaceType;
    guint16 interfaceId;
    guint16 freq;
    guint16 fractFreq;
    gfloat fullFreq;
    guint16 channel;
    guint8 phy;
    gint8 rssi;
    guint8 status;
    guint8 protocol;
    
    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < TI_RPI_MIN_LENGTH)
    return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TI-RPI");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    
    /* Add TI-RPI protocol as sub tree in the Wireshark display */
    ti = proto_tree_add_item(tree, proto_ti_rpi, tvb, 0, -1, ENC_NA);
    ti_rpi_tree = proto_item_add_subtree(ti, ett_ti_rpi);
    
    /* Display interface information */
    interfaceType = tvb_get_uint8(tvb, INTERFACE_TYPE_OFFSET);
    interfaceId = tvb_get_letohs(tvb, INTERFACE_ID_OFFSET);
    if(interfaceType == INTERFACE_TYPE_COM)
    {
        proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_interface, tvb, INTERFACE_ID_OFFSET, INTERFACE_ID_SIZE, "", "Interface: COM %d", interfaceId);
    }
    else if(interfaceType == INTERFACE_TYPE_CEBAL)
    {
        proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_interface, tvb, INTERFACE_ID_OFFSET, INTERFACE_ID_SIZE, "", "Interface: CEBAL 0x%x", interfaceId);
    }
    
    /* Display frequency and fractional frequency in MHz */
    freq = tvb_get_letohs(tvb, FREQUENCY_OFFSET);
    fractFreq = tvb_get_letohs(tvb, FRACTIONAL_FREQUENCY_OFFSET);
    /* Add fractional frequency (1/65535 fractions of 1 MHz) */ 
    fullFreq = freq + ((gfloat)fractFreq/65535);
    ti = proto_tree_add_float(ti_rpi_tree, hf_ti_rpi_frequency, tvb, FREQUENCY_OFFSET, FREQUENCY_SIZE, fullFreq);
    proto_item_append_text(ti, " MHz");
    
    /* Find value of protocol field */
    protocol = tvb_get_uint8(tvb, PROTOCOL_OFFSET);
    
    /* Display channel number except if protocol is generic. Generic protocols may not have a channel concept) */
    if(protocol != PROTOCOL_GENERIC)
    {
        channel = tvb_get_letohs(tvb, CHANNEL_OFFSET);
        proto_tree_add_uint(ti_rpi_tree, hf_ti_rpi_channel, tvb, CHANNEL_OFFSET, CHANNEL_SIZE, channel);
    }
    
    /* Display PHY type for generic and 15.4 protocol type, and if phy type has one of the known values */
    phy = tvb_get_uint8(tvb, PHY_OFFSET);
    
    if((protocol == PROTOCOL_GENERIC) || (protocol == PROTOCOL_IEEE_802_15_4_G))
    {
        ti = proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_phy, tvb, PHY_OFFSET, PHY_SIZE, "", "PHY: ");
        if(phy == PHY_TYPE_50KBPS_GFSK)
        {
            proto_item_append_text(ti, PHY_50KBPS_GFSK_STRING);
            
        }
        else if(phy == PHY_TYPE_SLR)
        {
            proto_item_append_text(ti, PHY_SLR_STRING);
        }
        else if(phy == PHY_TYPE_200KBPS_GFSK)
        {
            proto_item_append_text(ti, PHY_200KBPS_GFSK_STRING);
        }
        else if(phy == PHY_TYPE_50KBPS_GFSK_WISUN_1A)
        {
            proto_item_append_text(ti, PHY_50KBPS_GFSK_WISUN_1A_STRING);
        }
        else if(phy == PHY_TYPE_50KBPS_GFSK_WISUN_1B)
        {
            proto_item_append_text(ti, PHY_50KBPS_GFSK_WISUN_1B_STRING);
        }
        else if(phy == PHY_TYPE_100KBPS_GFSK_WISUN_2A)
        {
            proto_item_append_text(ti, PHY_100KBPS_GFSK_WISUN_2A_STRING);
        }
        else if(phy == PHY_TYPE_100KBPS_GFSK_WISUN_2B)
        {
            proto_item_append_text(ti, PHY_100KBPS_GFSK_WISUN_2B_STRING);
        }
        else if(phy == PHY_TYPE_150KBPS_GFSK_WISUN_3)
        {
            proto_item_append_text(ti, PHY_150KBPS_GFSK_WISUN_3_STRING);
        }
        else if(phy == PHY_TYPE_200KBPS_GFSK_WISUN_4A)
        {
            proto_item_append_text(ti, PHY_200KBPS_GFSK_WISUN_4A_STRING);
        }
        else if(phy == PHY_TYPE_200KBPS_GFSK_WISUN_4B)
        {
            proto_item_append_text(ti, PHY_200KBPS_GFSK_WISUN_4B_STRING);
        }
        else if(phy == PHY_TYPE_100KBPS_GFSK_ZIGBEE_R23)
        {
            proto_item_append_text(ti, PHY_100KBPS_GFSK_ZIGBEE_R23_STRING);
        }
        else if(phy == PHY_TYPE_500KBPS_GFSK_ZIGBEE_R23)
        {
            proto_item_append_text(ti, PHY_500KBPS_GFSK_ZIGBEE_R23_STRING);
        }
    }
    else if( (protocol == PROTOCOL_IEEE_802_15_4) && (phy == PHY_TYPE_OQPSK) )
    {
        ti = proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_phy, tvb, PHY_OFFSET, PHY_SIZE, "", "PHY: ");
        if(phy == PHY_TYPE_OQPSK)
        {
            proto_item_append_text(ti, PHY_OQPSK_STRING);
            
        }
    }
    else if( (protocol == PROTOCOL_BLE) && (phy == PHY_TYPE_BLE) )
    {
        ti = proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_phy, tvb, PHY_OFFSET, PHY_SIZE, "", "PHY: ");
        if(phy == PHY_TYPE_BLE)
        {
            proto_item_append_text(ti, PHY_BLE_STRING);
        }
    }
    else if(protocol == PROTOCOL_WBMS) 
    {
        ti = proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_phy, tvb, PHY_OFFSET, PHY_SIZE, "", "PHY: ");
        if(phy == PHY_TYPE_WBMS)
        {
            proto_item_append_text(ti, PHY_WBMS_STRING);
        }
    }
    
    /* Display RSSI value */
    rssi = (gint8)tvb_get_uint8(tvb, RSSI_OFFSET);
    ti = proto_tree_add_int(ti_rpi_tree, hf_ti_rpi_rssi, tvb, RSSI_OFFSET, RSSI_SIZE, rssi);
    proto_item_append_text(ti, " dBm");
    
    /* Display status */
    status = tvb_get_uint8(tvb, STATUS_OFFSET);
    ti = proto_tree_add_uint(ti_rpi_tree, hf_ti_rpi_status, tvb, STATUS_OFFSET, STATUS_SIZE, status);
    if(status == 0x80)
    {
        proto_item_append_text(ti, " - OK");
    }
    else
    {
        proto_item_append_text(ti, " - BAD FCS" );
    }
    
    /* Display payload length information */
    guint16 payloadLength = tvb_reported_length(tvb) - PAYLOAD_OFFSET;
    proto_tree_add_string_format(ti_rpi_tree, hf_ti_rpi_length, tvb, PAYLOAD_OFFSET, payloadLength, "", "Payload Length: %d Bytes", payloadLength);
    
    /* Forward payload to next dissector depending on protocol field value */
    tvbuff_t* payloadTvb = tvb_new_subset_remaining(tvb, PAYLOAD_OFFSET + 1);
    
    if(protocol == PROTOCOL_IEEE_802_15_4_G)
    {
        // Skip 2 bytes in payload for 802.15.4g. The 2 PHY Header bytes are not handled
        // by the IEEE 802.15.4 dissector. 
        payloadTvb = tvb_new_subset_remaining(payloadTvb, 2);
        call_dissector(legacy_ieee802154_handle, payloadTvb, pinfo, tree);
    }
    else if(protocol == PROTOCOL_IEEE_802_15_4)
    {
        call_dissector(legacy_ieee802154_handle, payloadTvb, pinfo, tree);
    }
    else if(protocol == PROTOCOL_BLE)
    {
        call_dissector(ble_handle, payloadTvb, pinfo, tree);
    }
    else if(protocol == PROTOCOL_WBMS)
    {
        if(!wbms_handle)
        {
            // Workaround for finding handle to WBMS dissector. 
            // The dissector is written in LUA and not registered at the time of calling proto_reg_handoff_ti_rpi
            // Therefore it is called again here. 
            wbms_handle = find_dissector("wbms_plrf");
        }
        call_dissector(wbms_handle, payloadTvb, pinfo, tree);
    }
    //
    else
    {
        /* For all other protocols use the generic data dissector */
        //call_dissector(legacy_ieee802154_handle, payloadTvb, pinfo, tree);
        call_dissector(tado_handle, payloadTvb, pinfo, tree);
    }
   
    return tvb_captured_length(tvb);
}


/*FUNCTION:------------------------------------------------------
*  NAME
*      proto_register_ti_rpi
*  DESCRIPTION
*      Register protocol and fields with Wireshark 
*
*  PARAMETERS
*      void
*  RETURNS
*      void
*---------------------------------------------------------------
*/
void
proto_register_ti_rpi(void)
{
    static hf_register_info hf[] = 
    {
        { &hf_ti_rpi_interface,
        { "Interface", "ti-rpi.if", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        
        { &hf_ti_rpi_frequency,
        { "Frequency", "ti-rpi.freq", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        
        { &hf_ti_rpi_channel,
        { "Channel", "ti-rpi.channel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        
        { &hf_ti_rpi_phy,
        { "PHY", "ti-rpi.phy", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        
        { &hf_ti_rpi_rssi,
        { "RSSI", "ti-rpi.rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        
        { &hf_ti_rpi_status,
        { "Frame Check Status", "ti-rpi.fcs", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        
        { &hf_ti_rpi_length,
        { "Payload Length", "ti-rpi.length", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = 
    {
        &ett_ti_rpi
    };

    /* Register the protocol name and description */
    proto_ti_rpi = proto_register_protocol("TI Radio Packet Info",
            "TI-RPI", "ti-rpi");
            
    register_dissector("ti-rpi",dissect_ti_rpi,proto_ti_rpi); 

    proto_register_field_array(proto_ti_rpi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


 
/*FUNCTION:------------------------------------------------------
*  NAME
*      proto_reg_handoff_ti_rpi
*  DESCRIPTION
*      Dissector handoff registration
*
*  PARAMETERS
*      void
*  RETURNS
*      void
*---------------------------------------------------------------
*/
void
proto_reg_handoff_ti_rpi(void)
{
    /* Get dissector handles */
    ti802154ge_handle = find_dissector(TI802154GE_PROTOABBREV_TI802154GE);
    ti802154ge_sun_phy_handle = find_dissector(TI802154GE_PROTOABBREV_SUNPHY_TI802154GE);
    //data_handle = find_dissector("data");
    tado_handle = find_dissector("tado");
    legacy_ieee802154_handle = find_dissector("wpan"); 
    ble_handle = find_dissector("ti-ble-pi");
    wbms_handle = find_dissector("wbms_plrf");
    sixlowpan_handle = find_dissector("6lowpan");
    
    /* Use new_create_dissector_handle() to indicate that dissect_ti_rpi()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to TI-RPI).
     */
    ti_rti_handle = create_dissector_handle(dissect_ti_rpi, proto_ti_rpi);
            
    
    dissector_add_uint("udp.port", TI_RPI_UDP_PORT, ti_rti_handle);
}




