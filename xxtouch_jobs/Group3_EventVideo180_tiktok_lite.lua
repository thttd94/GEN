local links = {
    "https://www.tiktok.com/t/ZSHoJkxP6/",
    "https://www.tiktok.com/t/ZSHoJvPdS",
    "https://www.tiktok.com/t/ZSHodvDhG",
    "https://www.tiktok.com/t/ZSHodCJUU/",
    "https://www.tiktok.com/t/ZSHodXPJh/",
    "https://www.tiktok.com/t/ZSHodwDAy/",
    "https://www.tiktok.com/t/ZSHodquAk/",
    "https://www.tiktok.com/t/ZSHo64x5h/",
    "https://www.tiktok.com/t/ZSHo6yxet/",
    "https://www.tiktok.com/t/ZSHoksvp6/",
}

math.randomseed(os.time())
math.random()
math.random()

local pick = links[math.random(1, #links)]

app.open_url(pick)

return true
