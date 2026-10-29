package media

var StandardSizes = SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1376, 768}, "9:16 1k": {768, 1376}, "4:3 1k": {1152, 864},
	"3:4 1k": {864, 1152}, "3:2 1k": {1248, 832}, "2:3 1k": {832, 1248},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2048, 1152}, "9:16 2k": {1152, 2048}, "4:3 2k": {2048, 1536},
	"3:4 2k": {1536, 2048}, "3:2 2k": {1920, 1280}, "2:3 2k": {1280, 1920},
})

var IdeogramSizes = SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1280, 720}, "9:16 1k": {720, 1280}, "4:3 1k": {1152, 864},
	"3:4 1k": {864, 1152}, "3:2 1k": {1248, 832}, "2:3 1k": {832, 1248},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2560, 1440}, "9:16 2k": {1440, 2560}, "4:3 2k": {2304, 1728},
	"3:4 2k": {1728, 2304}, "3:2 2k": {2496, 1664}, "2:3 2k": {1664, 2496},
})

var (
	Flux2Max        = ImageSpec{MaxReferences: 8}
	Flux2Pro        = ImageSpec{MaxReferences: 9}
	Seedream5Pro    = ImageSpec{MaxReferences: 10}
	Seedream5Lite   = ImageSpec{MaxReferences: 14}
	Seedream45      = ImageSpec{MaxReferences: 14}
	Ideogram45      = ImageSpec{MaxReferences: 5, Qualities: []string{"low", "medium", "high"}}
	QwenImage3      = ImageSpec{MaxReferences: 3}
	SDXLCheckpoint  = ImageSpec{Resolutions: []string{"1k"}}
	ZImageTurbo     = ImageSpec{}
	NanoBananaPro   = ImageSpec{MaxReferences: 14}
	NanoBanana2     = ImageSpec{MaxReferences: 14}
	NanoBanana2Lite = ImageSpec{MaxReferences: 14, Resolutions: []string{"1k"}}
)

var (
	KlingV3Pro     = VideoSpec{MinSeconds: 3, MaxSeconds: 15, Resolutions: []string{"1080p"}, Audio: true, LastFrame: true}
	Seedance25     = VideoSpec{MinSeconds: 4, MaxSeconds: 30, Resolutions: []string{"480p", "720p", "1080p"}, Audio: true, LastFrame: true}
	Seedance20Fast = VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"480p", "720p"}, Audio: true, LastFrame: true}
	MiniMaxH3Max   = VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"480p", "768p"}, LastFrame: true}
	Wan30          = VideoSpec{MinSeconds: 2, MaxSeconds: 30, Resolutions: []string{"480p", "720p", "1080p"}, Audio: true, LastFrame: true}
)
