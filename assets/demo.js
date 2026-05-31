// Static-demo glue: sidebar collapse, toasts, fake submits, modal, lang mirror.
(function () {
    var STR = (document.documentElement.lang || 'en').toLowerCase().startsWith('ru')
        ? {
            confirmTitle: 'Подтверждение',
            cancel: 'Отмена',
            confirm: 'Подтвердить',
            toastDemo: 'Демо без бэкенда — реальные операции отключены.',
            toastDownload: 'В реальном приложении был бы скачан файл',
            collapseTitle: 'Свернуть меню',
            expandTitle: 'Развернуть меню',
        }
        : {
            confirmTitle: 'Confirmation',
            cancel: 'Cancel',
            confirm: 'Confirm',
            toastDemo: 'Static demo — backend not connected.',
            toastDownload: 'In the real app this would download',
            collapseTitle: 'Collapse menu',
            expandTitle: 'Expand menu',
        };

    // ── Sidebar collapse ───────────────────────────────────
    // The demo always opens with the menu expanded (labels + section
    // headers visible) so the navigation explains itself. The toggle still
    // lets the visitor collapse it for the current page; the choice is not
    // persisted, so every page starts expanded again.
    document.addEventListener('DOMContentLoaded', function () {
        var toggle = document.getElementById('sidebar-toggle');
        if (toggle) {
            toggle.title = STR.collapseTitle;
            toggle.addEventListener('click', function () {
                document.body.classList.toggle('sidebar-collapsed');
                var on = document.body.classList.contains('sidebar-collapsed');
                toggle.title = on ? STR.expandTitle : STR.collapseTitle;
            });
        }

        // ── Intercept every form / submit-style button ────
        document.querySelectorAll('form.mock-form').forEach(function (f) {
            f.addEventListener('submit', function (e) {
                e.preventDefault();
                var msg = f.getAttribute('data-toast') || STR.toastDemo;
                showToast(msg, f.getAttribute('data-toast-type') || 'info');
            });
        });
        document.querySelectorAll('[data-mock-action]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                e.preventDefault();
                var msg = el.getAttribute('data-mock-msg') || STR.toastDemo;
                showToast(msg, el.getAttribute('data-toast-type') || 'info');
            });
        });
        document.querySelectorAll('[data-mock-download]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                e.preventDefault();
                var what = el.getAttribute('data-mock-download');
                showToast(STR.toastDownload + ': ' + what, 'info');
            });
        });

        // ── Column filter inputs on data tables (cosmetic) ─
        document.querySelectorAll('.datatable').forEach(function (tbl) {
            var head = tbl.querySelector('thead tr');
            if (!head) return;
            var ths = head.querySelectorAll('th');
            var row = document.createElement('tr');
            row.className = 'col-filter-row';
            ths.forEach(function () {
                var th = document.createElement('th');
                var inp = document.createElement('input');
                inp.className = 'col-filter-input';
                inp.placeholder = '▼';
                th.appendChild(inp);
                row.appendChild(th);
            });
            head.parentNode.appendChild(row);

            row.querySelectorAll('.col-filter-input').forEach(function (inp, idx) {
                inp.addEventListener('input', function () {
                    var q = inp.value.toLowerCase().trim();
                    tbl.querySelectorAll('tbody tr').forEach(function (tr) {
                        var cell = tr.children[idx];
                        if (!cell) return;
                        var has = !q || cell.textContent.toLowerCase().indexOf(q) >= 0;
                        var hide = tr.dataset._hideFor || '';
                        if (has) tr.dataset._hideFor = hide.replace(new RegExp('\\b' + idx + '\\b', 'g'), '').trim();
                        else if (!hide.split(' ').includes(String(idx))) tr.dataset._hideFor = (hide + ' ' + idx).trim();
                        tr.style.display = tr.dataset._hideFor ? 'none' : '';
                    });
                });
            });
        });

        // ── Confirm modal (lightweight) ────────────────────
        var modal = document.getElementById('confirm-modal');
        if (modal) {
            modal.addEventListener('click', function (e) {
                if (e.target === modal) modal.style.display = 'none';
            });
            modal.querySelector('[data-confirm-cancel]').addEventListener('click', function () {
                modal.style.display = 'none';
            });
        }
    });

    // ── Toast helper exposed globally ──────────────────────
    window.showToast = function (msg, type) {
        var t = document.createElement('div');
        t.className = 'toast' + (type ? ' toast-' + type : '');
        var ico = document.createElement('i');
        ico.className = 'fa fa-info-circle';
        ico.style.marginRight = '6px';
        t.appendChild(ico);
        t.appendChild(document.createTextNode(String(msg)));
        document.body.appendChild(t);
        t.addEventListener('click', function () { t.remove(); });
        setTimeout(function () {
            t.style.transition = 'opacity 0.4s';
            t.style.opacity = '0';
            setTimeout(function () { t.remove(); }, 400);
        }, 4500);
    };
})();
