#ifndef EN_SYNC_SB_H
#define EN_SYNC_SB_H 1

#include "lib/inc-proc-eng.h"

void *en_sync_to_sb_init(struct engine_node *, struct engine_arg *);
void en_sync_to_sb_run(struct engine_node *, void *data);
void en_sync_to_sb_cleanup(void *data);

void *en_sync_to_sb_addr_set_init(struct engine_node *, struct engine_arg *);
void en_sync_to_sb_addr_set_run(struct engine_node *, void *data);
void en_sync_to_sb_addr_set_cleanup(void *data);

bool sync_to_sb_addr_set_nb_address_set_handler(struct engine_node *,
                                                void *data);
bool sync_to_sb_addr_set_nb_port_group_handler(struct engine_node *,
                                               void *data);

#endif /* end of EN_SYNC_SB_H */
