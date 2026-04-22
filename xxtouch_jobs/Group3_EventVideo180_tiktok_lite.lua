local links = {
    "https://lite.tiktok.com/t/ZSHoJkxP6/",
    "https://lite.tiktok.com/t/ZSHoJvPdS",
    "https://lite.tiktok.com/t/ZSHodvDhG",
    "https://lite.tiktok.com/t/ZSHodCJUU/",
    "https://lite.tiktok.com/t/ZSHodXPJh/",
    "https://lite.tiktok.com/t/ZSHodwDAy/",
    "https://lite.tiktok.com/t/ZSHodquAk/",
    "https://lite.tiktok.com/t/ZSHo64x5h/",
    "https://lite.tiktok.com/t/ZSHo6yxet/",
    "https://lite.tiktok.com/t/ZSHoksvp6/",
}

math.randomseed(os.time())
math.random()
math.random()

local pick = links[math.random(1, #links)]

app.open_url(pick)

return true
