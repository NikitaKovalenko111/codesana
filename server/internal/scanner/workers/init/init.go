package scanner_init

type InitWorker struct{}

func Init() *InitWorker {
	return &InitWorker{}
}

func (w *InitWorker) Run() {

}
