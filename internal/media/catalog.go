package media

import "slices"

// why: FLUX.2, Seedream, Qwen, and Ideogram with references each draw multiples of 32 up to 2048 a side and 921,600 to
// 4,194,304 pixels.
var StandardSizes = SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1376, 768}, "9:16 1k": {768, 1376}, "4:3 1k": {1152, 864},
	"3:4 1k": {864, 1152}, "3:2 1k": {1248, 832}, "2:3 1k": {832, 1248},
	"21:9 1k": {1568, 672}, "4:5 1k": {896, 1120}, "5:4 1k": {1120, 896},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2048, 1152}, "9:16 2k": {1152, 2048}, "4:3 2k": {2048, 1536},
	"3:4 2k": {1536, 2048}, "3:2 2k": {1920, 1280}, "2:3 2k": {1280, 1920},
	"21:9 2k": {2016, 864}, "4:5 2k": {1632, 2048}, "5:4 2k": {2048, 1632},
})

// why: Ideogram 4.5 draws without a reference only at its text-to-image presets, and none is near 21:9 at 1k.
var IdeogramSizes = SizeTable(map[string][2]int{
	"1:1 1k": {1024, 1024}, "16:9 1k": {1280, 720}, "9:16 1k": {720, 1280}, "4:3 1k": {1152, 864},
	"3:4 1k": {864, 1152}, "3:2 1k": {1248, 832}, "2:3 1k": {832, 1248}, "4:5 1k": {896, 1120}, "5:4 1k": {1120, 896},
	"1:1 2k": {2048, 2048}, "16:9 2k": {2560, 1440}, "9:16 2k": {1440, 2560}, "4:3 2k": {2304, 1728},
	"3:4 2k": {1728, 2304}, "3:2 2k": {2496, 1664}, "2:3 2k": {1664, 2496}, "4:5 2k": {1792, 2240}, "5:4 2k": {2240, 1792},
})

var (
	upTo4K = []string{"1k", "2k", "4k"}
	only1K = []string{"1k"}
)

var (
	SevenRatios = without(AspectRatios, "21:9", "4:5", "5:4")
	UpTo2K      = []string{"1k", "2k"}
)

func without(ratios []string, drop ...string) []string {
	return slices.DeleteFunc(slices.Clone(ratios), func(r string) bool { return slices.Contains(drop, r) })
}

// why: fal's schemas (2026-10-15) give FLUX.2, Ideogram 4.5, Qwen-Image-3, and Z-Image Turbo a seed, Seedream 5.0 Pro
// none, and only Qwen a negative prompt (500 characters), none past about 4 MP; Runware's FLUX.2 and SDXL pages list
// seed, its SDXL page negativePrompt (3,000), and Seedream 5.0 Lite and 4.5 sizes at the seven ratios only.
var (
	Flux2Max        = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 8, Seed: true}
	Flux2Pro        = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 9, Seed: true}
	Seedream5Pro    = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 10}
	Seedream5Lite   = ImageSpec{AspectRatios: SevenRatios, Resolutions: UpTo2K, MaxReferences: 14}
	Seedream45      = ImageSpec{AspectRatios: SevenRatios, Resolutions: UpTo2K, MaxReferences: 14}
	Ideogram45      = ImageSpec{AspectRatios: without(AspectRatios, "21:9"), Resolutions: UpTo2K, MaxReferences: 5, Qualities: []string{"low", "medium", "high"}, Seed: true}
	QwenImage3      = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 3, Seed: true, NegativePrompt: 500}
	SDXLCheckpoint  = ImageSpec{AspectRatios: AspectRatios, Resolutions: only1K, Seed: true, NegativePrompt: MaxNegativePrompt}
	ZImageTurbo     = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, Seed: true}
	NanoBananaPro   = ImageSpec{AspectRatios: AspectRatios, Resolutions: upTo4K, MaxReferences: 14}
	NanoBanana2     = ImageSpec{AspectRatios: AspectRatios, Resolutions: upTo4K, MaxReferences: 14}
	NanoBanana2Lite = ImageSpec{AspectRatios: AspectRatios, Resolutions: only1K, MaxReferences: 14}
	GrokImagine2    = ImageSpec{AspectRatios: without(AspectRatios, "4:5", "5:4"), Resolutions: UpTo2K, MaxReferences: 5, Qualities: []string{"low", "medium"}}
)

// why: Runware's schemas (2026-11-22) draw Muse Image only at its 2K presets and Kling Image 4.0 from 2K up, neither
// at 4:5 or 5:4; GPT Image 2.6 takes 16 references, FLUX 3 Klein 4, and only Klein and Ideogram 4.6 a seed. Google
// lists Nano Banana 2.1 at 1K, 2K, and 4K, and xAI takes a quality only on Grok Imagine Image 2.0.
var (
	MuseImage    = ImageSpec{AspectRatios: without(AspectRatios, "4:5", "5:4"), Resolutions: []string{"2k"}, MaxReferences: 10}
	Seedream55   = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 10}
	KlingImage4  = ImageSpec{AspectRatios: without(AspectRatios, "4:5", "5:4"), Resolutions: []string{"2k", "4k"}, MaxReferences: 10}
	Flux3        = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 10}
	Flux3Klein   = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 4, Seed: true}
	GPTImage26   = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 16, Qualities: []string{"low", "medium", "high"}}
	Ideogram46   = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 5, Qualities: []string{"low", "medium", "high"}, Seed: true}
	NanoBanana21 = ImageSpec{AspectRatios: AspectRatios, Resolutions: upTo4K, MaxReferences: 14}
	GrokImagine1 = ImageSpec{AspectRatios: without(AspectRatios, "4:5", "5:4"), Resolutions: UpTo2K, MaxReferences: 5}
	MAIImage27   = ImageSpec{AspectRatios: AspectRatios, Resolutions: UpTo2K, MaxReferences: 5}
)

var (
	Upscale          = ImageSpec{Resolutions: []string{"2k", "4k"}, MaxReferences: 1, Seed: true, Prompt: PromptNone, Tool: ToolUpscale}
	RemoveBackground = ImageSpec{MaxReferences: 1, Prompt: PromptNone, Tool: ToolRemoveBackground}
	Inpaint          = ImageSpec{MaxReferences: 1, Seed: true, Mask: true, Tool: ToolInpaint}
)

func LongEdge(resolution string) int {
	switch resolution {
	case "2k":
		return 2048
	case "4k":
		return 4096
	}
	return 1024
}

var (
	KlingV3Pro     = VideoSpec{MinSeconds: 3, MaxSeconds: 15, Resolutions: []string{"1080p"}, Audio: true, LastFrame: true}
	Seedance25     = VideoSpec{MinSeconds: 4, MaxSeconds: 30, Resolutions: []string{"480p", "720p", "1080p"}, Audio: true, LastFrame: true}
	Seedance20Fast = VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"480p", "720p"}, Audio: true, LastFrame: true}
	MiniMaxH3Max   = VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"480p", "768p"}, LastFrame: true}
	Wan30          = VideoSpec{MinSeconds: 2, MaxSeconds: 30, Resolutions: []string{"480p", "720p", "1080p"}, Audio: true, LastFrame: true}
)

// why: Runware's schemas (2026-11-22) draw Gemini Omni Flash 1.2 at 16:9 and 9:16 only and cut a clip with a last frame
// to 10 s, so it takes none here, and take one frame on HeyGen Video 1; each model makes sound of its own except Seedance, whose switch it is.
var (
	GeminiOmniFlash12 = VideoSpec{MinSeconds: 3, MaxSeconds: 15, Resolutions: []string{"720p", "1080p"}, AspectRatios: []string{"16:9", "9:16"}}
	HeyGenVideo1      = VideoSpec{MinSeconds: 5, MaxSeconds: 30, Resolutions: []string{"480p", "768p"}}
	PVideo2Pro        = VideoSpec{MinSeconds: 5, MaxSeconds: 15, Resolutions: []string{"480p", "768p"}, LastFrame: true}
	MiniMaxH3         = VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"768p", "1440p"}, LastFrame: true}
	Seedance25Flash   = VideoSpec{MinSeconds: 4, MaxSeconds: 30, Resolutions: []string{"480p", "720p"}, Audio: true, LastFrame: true}
	Seedance20Mini    = VideoSpec{MinSeconds: 4, MaxSeconds: 15, Resolutions: []string{"480p", "720p"}, Audio: true, LastFrame: true}
)
