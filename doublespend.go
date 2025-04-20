package main


import "fmt"


type LedgerEntry struct {
    Serial uint64
    Tag1   string
    Tag2   string
}


func IdentifyDoubleSpenders(entries []LedgerEntry) []string {
    m := make(map[uint64][]LedgerEntry)
    for _, e := range entries {
        m[e.Serial] = append(m[e.Serial], e)
    }
    var dsList []string
    for sn, list := range m {
        if len(list) > 1 {
            id := fmt.Sprintf("reconstructed_for_serial_%d", sn)
            dsList = append(dsList, id)
        }
    }
    return dsList
}
