// Landing-page only: smooth-scroll for in-page anchors, copy-to-clipboard
// on the quickstart block, scroll-reveal for feature cards.
(function () {
    document.addEventListener('DOMContentLoaded', function () {
        // smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                var id = a.getAttribute('href').slice(1);
                var t = document.getElementById(id);
                if (!t) return;
                e.preventDefault();
                t.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });

        // copy quickstart
        var btn = document.querySelector('[data-copy-target]');
        if (btn) {
            btn.addEventListener('click', function () {
                var sel = btn.getAttribute('data-copy-target');
                var node = document.querySelector(sel);
                if (!node) return;
                var text = node.innerText.replace(/^\$\s/gm, '');
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(function () {
                        btn.textContent = btn.getAttribute('data-copied') || '✓ copied';
                        setTimeout(function () { btn.textContent = btn.dataset.label; }, 1600);
                    });
                }
            });
            btn.dataset.label = btn.textContent;
        }

        // scroll reveal
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (e.isIntersecting) {
                    e.target.style.opacity = '1';
                    e.target.style.transform = 'translateY(0)';
                    io.unobserve(e.target);
                }
            });
        }, { threshold: 0.12 });
        document.querySelectorAll('.feat, .tour-card, .algo-cell').forEach(function (n, i) {
            n.style.opacity = '0';
            n.style.transform = 'translateY(12px)';
            n.style.transition = 'opacity 0.5s ease ' + (i * 30) + 'ms, transform 0.5s ease ' + (i * 30) + 'ms';
            io.observe(n);
        });
    });
})();
