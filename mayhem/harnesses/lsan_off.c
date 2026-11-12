/* Leak detection is not the bug class fuzzed here: link this to turn LeakSanitizer off at build time. */
int __lsan_is_turned_off(void)
{
	return 1;
}
