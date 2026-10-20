(function () {
    'use strict';

    var i18nNode = document.getElementById('wh-i18n');
    var cfg = i18nNode ? JSON.parse(i18nNode.textContent) : {empty: 'No results', indexUrl: '', pageBase: ''};

    var sidebar = document.getElementById('wh-sidebar');
    var sidebarToggle = document.getElementById('wh-sidebar-toggle');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('wh-open-mobile');
        });
    }

    document.querySelectorAll('.wh-section-toggle').forEach(function (btn) {
        btn.addEventListener('click', function () {
            btn.parentElement.classList.toggle('wh-open');
        });
    });

    var input = document.getElementById('wh-search-input');
    var results = document.getElementById('wh-search-results');
    if (!input || !results) return;

    var index = null;
    function loadIndex() {
        if (index) return Promise.resolve(index);
        return fetch(cfg.indexUrl, {credentials: 'same-origin'})
            .then(function (r) { return r.json(); })
            .then(function (data) { index = data.items || []; return index; });
    }

    function clearChildren(node) {
        while (node.firstChild) node.removeChild(node.firstChild);
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = text;
        return node;
    }

    function renderResults(matches) {
        clearChildren(results);
        if (!matches.length) {
            results.appendChild(el('li', 'wh-search-empty', cfg.empty));
            results.classList.add('wh-open');
            return;
        }
        matches.slice(0, 12).forEach(function (m) {
            var li = document.createElement('li');
            var a = document.createElement('a');
            a.href = cfg.pageBase + m.slug + '/';
            a.appendChild(el('span', 'wh-r-section', m.section));
            a.appendChild(el('span', 'wh-r-title', m.title));
            if (m.excerpt) a.appendChild(el('span', 'wh-r-excerpt', m.excerpt));
            li.appendChild(a);
            results.appendChild(li);
        });
        results.classList.add('wh-open');
    }

    function search(q) {
        q = q.trim().toLowerCase();
        if (!q) { results.classList.remove('wh-open'); return; }
        loadIndex().then(function (items) {
            var matches = items.filter(function (it) {
                return it.title.toLowerCase().indexOf(q) !== -1
                    || it.section.toLowerCase().indexOf(q) !== -1
                    || (it.excerpt || '').toLowerCase().indexOf(q) !== -1;
            });
            renderResults(matches);
        });
    }

    input.addEventListener('input', function () { search(input.value); });
    input.addEventListener('focus', function () {
        if (input.value.trim()) results.classList.add('wh-open');
    });
    document.addEventListener('click', function (e) {
        if (!results.contains(e.target) && e.target !== input) {
            results.classList.remove('wh-open');
        }
    });
})();
