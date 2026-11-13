package schedule

import (
	"slices"
	"strings"
	"testing"
)

func bitsOf(set uint64) []int {
	var out []int
	for n := range 64 {
		if set&(1<<n) != 0 {
			out = append(out, n)
		}
	}
	return out
}

func TestACronReadsToTheValuesItsFieldsName(t *testing.T) {
	for _, c := range []struct {
		cron                      string
		minute                    int
		hours, doms, months, dows []int
		everyDom, everyDow        bool
	}{
		{"30 7 * * *", 30, []int{7}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"07 09 * * *", 7, []int{9}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 9-17/4 * * *", 0, []int{9, 13, 17}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 */6 * * *", 0, []int{0, 6, 12, 18}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 */7 * * *", 0, []int{0, 7, 14, 21}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 23-23 * * *", 0, []int{23}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 0-23/30 * * *", 0, []int{0}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 1,3,1 * * *", 0, []int{1, 3}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 */5,7 * * *", 0, []int{0, 5, 7, 10, 15, 20}, seq(1, 31), seq(1, 12), seq(0, 6), true, true},
		{"0 9 */1 * *", 0, []int{9}, seq(1, 31), seq(1, 12), seq(0, 6), false, true},
		{"0 9 */10 * *", 0, []int{9}, []int{1, 11, 21, 31}, seq(1, 12), seq(0, 6), false, true},
		{"0 9 1-7,15 */3 *", 0, []int{9}, []int{1, 2, 3, 4, 5, 6, 7, 15}, []int{1, 4, 7, 10}, seq(0, 6), false, true},
		{"0 9 * * 1-5", 0, []int{9}, seq(1, 31), seq(1, 12), []int{1, 2, 3, 4, 5}, true, false},
		{"0 9 * * 7", 0, []int{9}, seq(1, 31), seq(1, 12), []int{0}, true, false},
		{"0 9 * * 0,7", 0, []int{9}, seq(1, 31), seq(1, 12), []int{0}, true, false},
		{"0 9 * * 5-7", 0, []int{9}, seq(1, 31), seq(1, 12), []int{0, 5, 6}, true, false},
		{"0 9 * * */2", 0, []int{9}, seq(1, 31), seq(1, 12), []int{0, 2, 4, 6}, true, false},
		{"0 9 * * */7", 0, []int{9}, seq(1, 31), seq(1, 12), []int{0}, true, false},
		{"59 23 31 12 *", 59, []int{23}, []int{31}, []int{12}, seq(0, 6), false, true},
		{"0 9 29 2 *", 0, []int{9}, []int{29}, []int{2}, seq(0, 6), false, true},
	} {
		got, err := readCron(Custom, c.cron)
		if err != nil {
			t.Errorf("%q: %v", c.cron, err)
			continue
		}
		if got.minute != c.minute || !slices.Equal(bitsOf(got.hours), c.hours) || !slices.Equal(bitsOf(got.doms), c.doms) || !slices.Equal(bitsOf(got.months), c.months) || !slices.Equal(bitsOf(got.dows), c.dows) || got.everyDom != c.everyDom || got.everyDow != c.everyDow {
			t.Errorf("%q read as minute %d hours %v doms %v months %v dows %v, every dom %t, every dow %t", c.cron, got.minute, bitsOf(got.hours), bitsOf(got.doms), bitsOf(got.months), bitsOf(got.dows), got.everyDom, got.everyDow)
		}
	}
}

func seq(from, to int) []int {
	var out []int
	for n := from; n <= to; n++ {
		out = append(out, n)
	}
	return out
}

func TestACronIsRefusedByTheFirstRuleItBreaks(t *testing.T) {
	long := "00 9 " + strings.Repeat("01,", 30) + "31 * *"
	for _, c := range []struct {
		kind Kind
		cron string
		want Code
	}{
		{Custom, "0 9 * *", CodeCronSyntax},
		{Custom, "0 9 * * * *", CodeCronSyntax},
		{Custom, "0  9 * * *", CodeCronSyntax},
		{Custom, " 0 9 * * *", CodeCronSyntax},
		{Custom, "0 9 * * * ", CodeCronSyntax},
		{Custom, "0\t9 * * *", CodeCronSyntax},
		{Custom, "0 9 * * MON", CodeCronSyntax},
		{Custom, "0 9 * JAN *", CodeCronSyntax},
		{Custom, "0 9 ? * *", CodeCronSyntax},
		{Custom, "0 9 L * *", CodeCronSyntax},
		{Custom, "0 9 15W * *", CodeCronSyntax},
		{Custom, "0 9 * * 1#2", CodeCronSyntax},
		{Custom, "0 9 * * 1-", CodeCronSyntax},
		{Custom, "0 9 * * -5", CodeCronSyntax},
		{Custom, "0 9 1,,2 * *", CodeCronSyntax},
		{Custom, "0 9 1, * *", CodeCronSyntax},
		{Custom, "0 9 */ * *", CodeCronSyntax},
		{Custom, "0 9 5/2 * *", CodeCronSyntax},
		{Custom, "0 9 1-5/2/3 * *", CodeCronSyntax},
		{Custom, "0 9 *,1 * *", CodeCronSyntax},
		{Custom, "0 9 ** * *", CodeCronSyntax},
		{Custom, "0 100 * * *", CodeCronSyntax},
		{Custom, "0 9 * * 007", CodeCronSyntax},
		{Custom, "+5 9 * * *", CodeCronSyntax},
		{Custom, "0x1 9 * * *", CodeCronSyntax},
		{Custom, "٣ 9 * * *", CodeCronSyntax},
		{Custom, "@daily", CodeCronSyntax},
		{Custom, long, CodeCronSyntax},
		{Custom, "x 60 * * *", CodeCronSyntax},
		{Custom, "0 25,x * * *", CodeCronSyntax},
		{Custom, "60 9 * * *", CodeCronRange},
		{Custom, "0 24 * * *", CodeCronRange},
		{Custom, "0 9 0 * *", CodeCronRange},
		{Custom, "0 9 32 * *", CodeCronRange},
		{Custom, "0 9 * 0 *", CodeCronRange},
		{Custom, "0 9 * 13 *", CodeCronRange},
		{Custom, "0 9 * * 8", CodeCronRange},
		{Custom, "0 9 * * 5-3", CodeCronRange},
		{Custom, "0 9-17/0 * * *", CodeCronRange},
		{Custom, "0 */0 * * *", CodeCronRange},
		{Custom, "60 x * * *", CodeCronRange},
		{Custom, "0,30 24 * * *", CodeCronRange},
		{Custom, "* 9 * * *", CodeCronMinute},
		{Custom, "0,30 * * * *", CodeCronMinute},
		{Custom, "0-30 9 * * *", CodeCronMinute},
		{Custom, "5-5 9 * * *", CodeCronMinute},
		{Custom, "*/15 * * * *", CodeCronMinute},
		{Custom, "*/60 9 * * *", CodeCronMinute},
		{Custom, "*/15 9 1 * 1", CodeCronMinute},
		{Custom, "0 9 1 * 1", CodeCronDays},
		{Custom, "0 9 1-7 * 1", CodeCronDays},
		{Custom, "0 9 */1 * */1", CodeCronDays},
		{Custom, "0 9 31 2 1", CodeCronDays},
		{Daily, "0 9 1 * 1", CodeCronDays},
		{Hourly, "0 9 * * *", CodeCronShape},
		{Hourly, "0 * * * 1", CodeCronShape},
		{Hourly, "0 */1 * * *", CodeCronShape},
		{Daily, "0 * * * *", CodeCronShape},
		{Daily, "0 9-17 * * *", CodeCronShape},
		{Daily, "0 9 * * 1-5", CodeCronShape},
		{Daily, "0 9 1 * *", CodeCronShape},
		{Daily, "0 9 * 1 *", CodeCronShape},
		{Weekdays, "0 9 * * 1-6", CodeCronShape},
		{Weekdays, "0 9 * * 1,2,3,4,5", CodeCronShape},
		{Weekdays, "0 9 * * 01-05", CodeCronShape},
		{Weekdays, "0 9 * * 1-5/1", CodeCronShape},
		{Weekly, "0 9 * * 7", CodeCronShape},
		{Weekly, "0 9 * * 1,3", CodeCronShape},
		{Weekly, "0 9 * * *", CodeCronShape},
		{Weekly, "0 9 1 * *", CodeCronShape},
		{Weekly, "0 9 30 2 *", CodeCronShape},
		{Custom, "0 9 30 2 *", CodeCronNever},
		{Custom, "0 9 30,31 2 *", CodeCronNever},
		{Custom, "0 9 31 4,6,9,11 *", CodeCronNever},
		{Custom, "0 9 31 2-4/2 *", CodeCronNever},
		{Custom, long[1:], ""},
		{Custom, "0 9 29 2 *", ""},
		{Custom, "0 9 31 3-4 *", ""},
		{Custom, "0 9 */1 * *", ""},
		{Hourly, "05 * * * *", ""},
		{Daily, "0 07 * * *", ""},
		{Weekdays, "30 6 * * 1-5", ""},
		{Weekly, "0 9 * * 06", ""},
		{Weekly, "0 9 * * 0", ""},
	} {
		_, err := readCron(c.kind, c.cron)
		got, _ := CodeOf(err)
		if got != c.want || (err == nil) != (c.want == "") {
			t.Errorf("%s %q: %q (%v), want %q", c.kind, c.cron, got, err, c.want)
		}
	}
	if len(long) != MaxCron+1 || len(long[1:]) != MaxCron {
		t.Fatalf("the long crons are %d and %d bytes, want %d and %d", len(long), len(long[1:]), MaxCron+1, MaxCron)
	}
}

func TestACronThatNeverRunsFindsNoRunAndSaysSo(t *testing.T) {
	never := cron{minute: 0, hours: 1 << 9, doms: 1 << 30, months: 1 << 2, dows: span(0, 6, 1), everyDow: true}
	if at, ok := never.next(zone(t, "UTC"), utc(t, "2026-10-27T12:00:00Z")); ok {
		t.Errorf("a cron for 30 February ran at %s", at)
	}
}
