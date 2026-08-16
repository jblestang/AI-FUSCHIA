package compile

import "testing"

func TestConstantTableAppendOnlySlots(t *testing.T) {
	const pkgPath = "example.com/app"
	for i := 0; i < 100; i++ {
		seed := "stability-seed-" + seedPad3(i)
		table := newConstantTable(seed, pkgPath)
		a := table.register("const:int:0:100", 100)
		b := table.register("const:int:1:200", 200)
		if a.idxA == b.idxA || a.idxA == b.idxB || a.idxB == b.idxA || a.idxB == b.idxB {
			t.Fatalf("seed %q: slot collision between constants", seed)
		}
		if got := table.slots[a.idxA] ^ table.slots[a.idxB]; got != 100 {
			t.Fatalf("seed %q: first constant = %d, want 100", seed, got)
		}
		if got := table.slots[b.idxA] ^ table.slots[b.idxB]; got != 200 {
			t.Fatalf("seed %q: second constant = %d, want 200", seed, got)
		}
	}
}

func seedPad3(n int) string {
	return [...]string{
		"000", "001", "002", "003", "004", "005", "006", "007", "008", "009",
		"010", "011", "012", "013", "014", "015", "016", "017", "018", "019",
		"020", "021", "022", "023", "024", "025", "026", "027", "028", "029",
		"030", "031", "032", "033", "034", "035", "036", "037", "038", "039",
		"040", "041", "042", "043", "044", "045", "046", "047", "048", "049",
		"050", "051", "052", "053", "054", "055", "056", "057", "058", "059",
		"060", "061", "062", "063", "064", "065", "066", "067", "068", "069",
		"070", "071", "072", "073", "074", "075", "076", "077", "078", "079",
		"080", "081", "082", "083", "084", "085", "086", "087", "088", "089",
		"090", "091", "092", "093", "094", "095", "096", "097", "098", "099",
	}[n]
}
