(function () {
    // 获取页面参数
    var params = new URLSearchParams(window.location.search);
    var aff = escapeHtml(params.get('aff'));
    if (aff) {
        $.cookie(PROMOTION_COOKIE_NAME, aff, { expires: PROMOTION_COOKIE_EXPIRES, domain: '.raksmart.com', path: '/' });
    }
})();

function escapeHtml(text) {
    if (!text) {
        return "";
    }
    var map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

function setBeforeLogin() {
    localStorage.setItem("beforeLogin", location.pathname + location.search);
}

function getBeforeLogin() {
    var beforeLogin = localStorage.getItem("beforeLogin");
    localStorage.removeItem('beforeLogin');
    if (beforeLogin) {
        var login = $.cookie(LOGIN_COOKIE_NAME);
        if (login) {
            location.href = beforeLogin;
        }
    }
}