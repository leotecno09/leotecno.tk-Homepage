// GET RANDOM SITE
let sites = ["https://minecraft.leotecno.tk", "https://short.leotecno.tk", "https://maxwell.leotecno.tk", "https://git.leotecno.tk", "https://francy.leotecno.tk"]

function getRandomSite() {
    var site = sites[(Math.floor(Math.random() * sites.length))];
    console.log(site)

    $('body').fadeOut(1000, function () {
        window.location.href = site;
    });
}