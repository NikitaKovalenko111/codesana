package scanner_report

type ReportWorker struct {
	codesanaWD string
}

func Init(codesanaWD string) *ReportWorker {
	return &ReportWorker{
		codesanaWD: codesanaWD,
	}
}

func (w *ReportWorker) MakePDF() {

}
