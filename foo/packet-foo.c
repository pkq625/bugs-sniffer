#include "config.h"
#include <epan/packet.h>

#define FOO_PORT 9999   /*the port foo use*/

static int proto_foo = -1;        // register this protocol
static gint ett_foo = -1;         // for the display tree
// the protocol content: 
static int hf_foo_pdu_type = -1;  // type
static int hf_foo_pdu_flags = -1; // flags
static int hf_foo_seqnum = -1;    // seq num
static int hf_foo_initip = -1;      // initial

static int dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_){
    proto_item* ti = NULL;
    proto_tree* foo_tree = NULL;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "foo dissector");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    
    if(NULL != tree){
        ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
        foo_tree = proto_item_add_subtree(ti, ett_foo);
        proto_tree_add_item(foo_tree, hf_foo_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1; 
        proto_tree_add_item(foo_tree, hf_foo_pdu_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1; 
        proto_tree_add_item(foo_tree, hf_foo_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2; 
        proto_tree_add_item(foo_tree, hf_foo_initip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4; 
    }
    return tvb_captured_length(tvb);
}

void proto_register_foo(void){
    static hf_register_info hf[] = {
        {&hf_foo_pdu_type, {"Foo Type", "foo.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_foo_pdu_flags, {"Foo Flags", "foo.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_foo_seqnum, {"Foo Sequence number", "foo.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_foo_initip, {"Foo Initial IP", "foo.initip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };
    static gint* ett[] = {&ett_foo};

    proto_foo = proto_register_protocol (
    "FOO Protocol", /* name */
    "Foo", /* short_name */
    "foo" /* filter_name */
    );
    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_foo(void){
    static dissector_handle_t foo_handle;
    
    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
