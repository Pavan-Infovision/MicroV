cmd_/home/user/working/hypervisor/loader/linux/bareflank_loader.o := ld -m elf_x86_64  -z max-page-size=0x200000    -r -o /home/user/working/hypervisor/loader/linux/bareflank_loader.o /home/user/working/hypervisor/loader/linux/src/entry.o /home/user/working/hypervisor/loader/linux/src/platform.o /home/user/working/hypervisor/loader/linux/../src/alloc_and_copy_ext_elf_files_from_user.o /home/user/working/hypervisor/loader/linux/../src/alloc_and_copy_mk_elf_file_from_user.o /home/user/working/hypervisor/loader/linux/../src/alloc_and_copy_mk_elf_segments.o /home/user/working/hypervisor/loader/linux/../src/alloc_mk_args.o /home/user/working/hypervisor/loader/linux/../src/alloc_mk_debug_ring.o /home/user/working/hypervisor/loader/linux/../src/alloc_mk_huge_pool.o /home/user/working/hypervisor/loader/linux/../src/alloc_mk_page_pool.o /home/user/working/hypervisor/loader/linux/../src/alloc_mk_stack.o /home/user/working/hypervisor/loader/linux/../src/dump_ext_elf_files.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_args.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_debug_ring.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_elf_file.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_elf_segments.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_huge_pool.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_page_pool.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_root_page_table.o /home/user/working/hypervisor/loader/linux/../src/dump_mk_stack.o /home/user/working/hypervisor/loader/linux/../src/dump_vmm.o /home/user/working/hypervisor/loader/linux/../src/free_ext_elf_files.o /home/user/working/hypervisor/loader/linux/../src/free_mk_args.o /home/user/working/hypervisor/loader/linux/../src/free_mk_debug_ring.o /home/user/working/hypervisor/loader/linux/../src/free_mk_elf_file.o /home/user/working/hypervisor/loader/linux/../src/free_mk_elf_segments.o /home/user/working/hypervisor/loader/linux/../src/free_mk_huge_pool.o /home/user/working/hypervisor/loader/linux/../src/free_mk_page_pool.o /home/user/working/hypervisor/loader/linux/../src/free_mk_stack.o /home/user/working/hypervisor/loader/linux/../src/g_cpu_status.o /home/user/working/hypervisor/loader/linux/../src/g_ext_elf_files.o /home/user/working/hypervisor/loader/linux/../src/g_mk_args.o /home/user/working/hypervisor/loader/linux/../src/g_mk_code_aliases.o /home/user/working/hypervisor/loader/linux/../src/g_mk_debug_ring.o /home/user/working/hypervisor/loader/linux/../src/g_mk_elf_file.o /home/user/working/hypervisor/loader/linux/../src/g_mk_elf_segments.o /home/user/working/hypervisor/loader/linux/../src/g_mk_huge_pool.o /home/user/working/hypervisor/loader/linux/../src/g_mk_page_pool.o /home/user/working/hypervisor/loader/linux/../src/g_mk_root_page_table.o /home/user/working/hypervisor/loader/linux/../src/g_mk_stack.o /home/user/working/hypervisor/loader/linux/../src/g_mk_state.o /home/user/working/hypervisor/loader/linux/../src/g_root_vp_state.o /home/user/working/hypervisor/loader/linux/../src/g_vmm_status.o /home/user/working/hypervisor/loader/linux/../src/get_mk_huge_pool_addr.o /home/user/working/hypervisor/loader/linux/../src/get_mk_page_pool_addr.o /home/user/working/hypervisor/loader/linux/../src/loader_fini.o /home/user/working/hypervisor/loader/linux/../src/loader_init.o /home/user/working/hypervisor/loader/linux/../src/map_4k_page_rw.o /home/user/working/hypervisor/loader/linux/../src/map_4k_page_rx.o /home/user/working/hypervisor/loader/linux/../src/map_ext_elf_files.o /home/user/working/hypervisor/loader/linux/../src/map_mk_args.o /home/user/working/hypervisor/loader/linux/../src/map_mk_debug_ring.o /home/user/working/hypervisor/loader/linux/../src/map_mk_elf_file.o /home/user/working/hypervisor/loader/linux/../src/map_mk_elf_segments.o /home/user/working/hypervisor/loader/linux/../src/map_mk_huge_pool.o /home/user/working/hypervisor/loader/linux/../src/map_mk_page_pool.o /home/user/working/hypervisor/loader/linux/../src/map_mk_stack.o /home/user/working/hypervisor/loader/linux/../src/serial_write.o /home/user/working/hypervisor/loader/linux/../src/start_vmm.o /home/user/working/hypervisor/loader/linux/../src/start_vmm_per_cpu.o /home/user/working/hypervisor/loader/linux/../src/stop_and_free_the_vmm.o /home/user/working/hypervisor/loader/linux/../src/stop_vmm.o /home/user/working/hypervisor/loader/linux/../src/stop_vmm_per_cpu.o /home/user/working/hypervisor/loader/linux/src/x64/demote.o /home/user/working/hypervisor/loader/linux/src/x64/esr_default.o /home/user/working/hypervisor/loader/linux/src/x64/esr_df.o /home/user/working/hypervisor/loader/linux/src/x64/esr_gpf.o /home/user/working/hypervisor/loader/linux/src/x64/esr_nmi.o /home/user/working/hypervisor/loader/linux/src/x64/esr_pf.o /home/user/working/hypervisor/loader/linux/src/x64/flush_cache.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_cpuid.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_inb.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_lcr4.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_outb.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_rdmsr.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr0.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scr4.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_scs.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sds.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_ses.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sfs.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sgdt.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sgs.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sidt.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sldtr.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_sss.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_str.o /home/user/working/hypervisor/loader/linux/src/x64/intrinsic_wrmsr.o /home/user/working/hypervisor/loader/linux/src/x64/promote.o /home/user/working/hypervisor/loader/linux/src/x64/serial_write_c.o /home/user/working/hypervisor/loader/linux/src/x64/serial_write_hex.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_and_copy_mk_code_aliases.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_and_copy_mk_state.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_and_copy_root_vp_state.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_mk_root_page_table.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_pdpt.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_pdt.o /home/user/working/hypervisor/loader/linux/../src/x64/alloc_pt.o /home/user/working/hypervisor/loader/linux/../src/x64/dump_mk_code_aliases.o /home/user/working/hypervisor/loader/linux/../src/x64/dump_mk_state.o /home/user/working/hypervisor/loader/linux/../src/x64/dump_root_vp_state.o /home/user/working/hypervisor/loader/linux/../src/x64/free_mk_code_aliases.o /home/user/working/hypervisor/loader/linux/../src/x64/free_mk_root_page_table.o /home/user/working/hypervisor/loader/linux/../src/x64/free_mk_state.o /home/user/working/hypervisor/loader/linux/../src/x64/free_pdpt.o /home/user/working/hypervisor/loader/linux/../src/x64/free_pdt.o /home/user/working/hypervisor/loader/linux/../src/x64/free_pml4t.o /home/user/working/hypervisor/loader/linux/../src/x64/free_root_vp_state.o /home/user/working/hypervisor/loader/linux/../src/x64/get_gdt_descriptor_attrib.o /home/user/working/hypervisor/loader/linux/../src/x64/get_gdt_descriptor_base.o /home/user/working/hypervisor/loader/linux/../src/x64/get_gdt_descriptor_limit.o /home/user/working/hypervisor/loader/linux/../src/x64/map_4k_page.o /home/user/working/hypervisor/loader/linux/../src/x64/map_mk_code_aliases.o /home/user/working/hypervisor/loader/linux/../src/x64/map_mk_state.o /home/user/working/hypervisor/loader/linux/../src/x64/map_root_vp_state.o /home/user/working/hypervisor/loader/linux/../src/x64/send_command_report_off.o /home/user/working/hypervisor/loader/linux/../src/x64/send_command_report_on.o /home/user/working/hypervisor/loader/linux/../src/x64/send_command_stop.o /home/user/working/hypervisor/loader/linux/../src/x64/serial_init.o /home/user/working/hypervisor/loader/linux/../src/x64/set_gdt_descriptor.o /home/user/working/hypervisor/loader/linux/../src/x64/set_idt_descriptor.o /home/user/working/hypervisor/loader/linux/src/x64/amd/disable_interrupts.o /home/user/working/hypervisor/loader/linux/src/x64/amd/enable_interrupts.o /home/user/working/hypervisor/loader/linux/../src/x64/amd/check_cpu_configuration.o /home/user/working/hypervisor/loader/linux/../src/x64/amd/disable_hve.o /home/user/working/hypervisor/loader/linux/../src/x64/amd/enable_hve.o
