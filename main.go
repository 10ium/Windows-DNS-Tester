package main

import (
	"embed"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// این متغیر در زمان بیلد در گیت‌هاب اکشن مقداردهی خودکار می‌شود
var Version = "1.0.0-dev"

// بارگذاری فایل‌های فرانت‌اند که در گام بعدی می‌سازیم
//go:embed all:frontend
var assets embed.FS

func main() {
	app := NewApp()
	app.version = Version

	err := wails.Run(&options.App{
		Title:  "Smart DNS Tester",
		Width:  1024,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1}, // Slate-900 (تاریک ملایم)
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
