-- The reconciler appends authenticated GET observations; it cannot rewrite them.
GRANT SELECT, INSERT ON kernel.delivery_events TO mk_kernel_worker;
