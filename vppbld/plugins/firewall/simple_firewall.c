/* Description : a simple firewall in Sonic-vpp to drop matching packets with specific IP
 * Author : Vishal Kapoor
 */



#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

static u32 blocked_ip;

static void set_blocked_ip(const char *ip_str) {
    struct in_addr ip_addr;
    if (inet_aton(ip_str, &ip_addr)) {
        blocked_ip = clib_host_to_net_u32(ip_addr.s_addr);
    } else {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
    }
}

static uword simple_firewall_node(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 *buffers = vlib_frame_vector_args(frame);
    u32 n_packets = frame->n_vectors;

    for (u32 i = 0; i < n_packets; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, buffers[i]);
        ip4_header_t *ip = vlib_buffer_get_current(b);

        if (ip->src_address.as_u32 == blocked_ip) {
            vlib_node_increment_counter(vm, node->node_index, 0, 1);
            continue; // Drop packet
        }

        vlib_buffer_enqueue_to_next(vm, node, buffers[i], VNET_DEVICE_INPUT_NEXT_IP4_LOOKUP);
    }

    return n_packets;
}

VLIB_REGISTER_NODE(firewall_node) = {
    .function = simple_firewall_node,
    .name = "firewall-drop-ip",
    .vector_size = sizeof(u32),
    .format_trace = format_ip4_header,
};
