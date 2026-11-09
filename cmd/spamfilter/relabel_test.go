package main

import "testing"

func TestOfferGroup(t *testing.T) {
	yes := []string{"misc.jobs.offered", "alt.bestjobsusa.jobs.offered", "biz.jobs.offerd", "nl.markt.banen",
		"rec.games.trading-cards.marketplace.magic.sales", "alt.pl.regionalne.opole.ogloszenia", "relcom.commerce.machinery",
		"tw.bbs.forsale.house", "tw.bbs.campus.job", "comp.os.linux.announce", "alt.test, biz.marketplace", "de.markt.biete"}
	no := []string{"alt.jobsearch.tips", "comp.dcom.xdsl", "alt.adsl", "rec.arts.marketing-history", "alt.bbs.waffle,alt.bbs.watergate",
		"news.admin.net-abuse.sightings", "sci.physics", "alt.salesmen"}
	for _, g := range yes {
		if !offerGroup.MatchString(g) {
			t.Errorf("%q: not matched", g)
		}
	}
	for _, g := range no {
		if offerGroup.MatchString(g) {
			t.Errorf("%q: matched", g)
		}
	}
}
