// Клиентское подписание через КриптоПро ЭЦП Browser plug-in.
// Документ скачивается в браузер, подписывается локальным ключом с USB-токена,
// подпись отправляется на бэкенд.

(function () {
  var API = '/api';

  // Константы CAdESCOM / CAPICOM
  var CAPICOM_CURRENT_USER_STORE = 2;
  var CAPICOM_MY_STORE = 'My';
  var CAPICOM_STORE_OPEN_READ_ONLY = 0;
  var CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
  var CADESCOM_CADES_BES = 1;
  var CADESCOM_BASE64_TO_BINARY = 1;

  // Экспорт сразу, до определения тел функций.
  // Имена async function-деклараций хойстятся, поэтому ссылки валидны.
  window.RbSignLocal = {
    listCertificates: listCertificates,
    signDocument: signDocument,
    showCertificateDialog: showCertificateDialog,
  };

  function ensurePlugin() {
    if (typeof cadesplugin === 'undefined') {
      throw new Error('Установите КриптоПро ЭЦП Browser plug-in (https://www.cryptopro.ru/products/cades/plugin)');
    }
    return cadesplugin;
  }

  async function listCertificates() {
    var cades = ensurePlugin();
    await cades;

    var store = await cades.CreateObjectAsync('CAdESCOM.Store');
    await store.Open(
      CAPICOM_CURRENT_USER_STORE,
      CAPICOM_MY_STORE,
      CAPICOM_STORE_OPEN_READ_ONLY
    );

    var certs = await store.Certificates;
    var count = await certs.Count;
    var result = [];

    for (var i = 1; i <= count; i++) {
      var cert = await certs.Item(i);
      try {
        result.push({
          thumbprint: await cert.Thumbprint,
          subjectName: await cert.SubjectName,
          issuerName: await cert.IssuerName,
          validFrom: await cert.ValidFromDate,
          validTo: await cert.ValidToDate,
        });
      } catch (e) {
        // сертификат недоступен — пропускаем
      }
    }

    await store.Close();
    return result;
  }

  async function signDocument(docId, thumbprint) {
    var cades = ensurePlugin();
    await cades;

    var res = await fetch(API + '/documents/' + docId + '/content-base64');
    if (!res.ok) throw new Error('Не удалось получить документ: ' + (await res.text()));
    var data = await res.json();
    var contentBase64 = data.content;

    var store = await cades.CreateObjectAsync('CAdESCOM.Store');
    await store.Open(
      CAPICOM_CURRENT_USER_STORE,
      CAPICOM_MY_STORE,
      CAPICOM_STORE_OPEN_READ_ONLY
    );
    var certs = await store.Certificates;
    var found = await certs.Find(CAPICOM_CERTIFICATE_FIND_SHA1_HASH, thumbprint);
    var foundCount = await found.Count;
    if (foundCount < 1) {
      await store.Close();
      throw new Error('Сертификат не найден: ' + thumbprint);
    }
    var cert = await found.Item(1);

    var signer = await cades.CreateObjectAsync('CAdESCOM.CPSigner');
    await signer.propset_Certificate(cert);

    var signedData = await cades.CreateObjectAsync('CAdESCOM.CadesSignedData');
    await signedData.propset_ContentEncoding(CADESCOM_BASE64_TO_BINARY);
    await signedData.propset_Content(contentBase64);

    var signature;
    try {
      signature = await signedData.SignCades(signer, CADESCOM_CADES_BES, true);
    } catch (e) {
      await store.Close();
      var msg = (e && e.message) ? e.message : String(e);
      if (msg.indexOf('0x8010006E') !== -1 || msg.toLowerCase().indexOf('cancel') !== -1) {
        throw new Error('Подписание отменено пользователем');
      }
      throw new Error('Ошибка создания подписи: ' + msg);
    }
    await store.Close();

    var sendRes = await fetch(API + '/documents/' + docId + '/sign-local', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signature_base64: signature }),
    });
    if (!sendRes.ok) throw new Error('Сервер отклонил подпись: ' + (await sendRes.text()));
    return await sendRes.json();
  }

  function formatDate(v) {
    if (!v) return '';
    try {
      var d = new Date(v);
      if (!isNaN(d.getTime())) {
        return d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
      }
    } catch (e) {}
    return String(v);
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function ensureDialogStyles() {
    if (document.getElementById('sign-local-styles')) return;
    var style = document.createElement('style');
    style.id = 'sign-local-styles';
    style.textContent = [
      '.sl-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:10000;}',
      '.sl-modal{background:#fff;border-radius:8px;padding:20px;max-width:640px;width:90%;max-height:80vh;overflow:auto;box-shadow:0 8px 32px rgba(0,0,0,.2);}',
      '.sl-modal h3{margin:0 0 12px;font-size:18px;}',
      '.sl-cert{border:1px solid #ddd;border-radius:6px;padding:10px 12px;margin-bottom:8px;cursor:pointer;transition:background .15s,border-color .15s;}',
      '.sl-cert:hover{background:#f0f7ff;border-color:#4a90d9;}',
      '.sl-cert .sl-subj{font-weight:600;margin-bottom:4px;}',
      '.sl-cert .sl-meta{font-size:12px;color:#666;}',
      '.sl-footer{margin-top:12px;text-align:right;}',
      '.sl-msg{padding:12px;text-align:center;color:#666;}',
      '.sl-error{color:#c00;}',
      '.sl-spinner{display:inline-block;width:14px;height:14px;border:2px solid #ccc;border-top-color:#4a90d9;border-radius:50%;animation:sl-spin 0.8s linear infinite;vertical-align:middle;margin-right:6px;}',
      '@keyframes sl-spin{to{transform:rotate(360deg);}}',
    ].join('');
    document.head.appendChild(style);
  }

  function closeDialog() {
    var el = document.getElementById('sl-overlay');
    if (el) el.remove();
  }

  function renderDialog(innerHtml) {
    ensureDialogStyles();
    closeDialog();
    var overlay = document.createElement('div');
    overlay.id = 'sl-overlay';
    overlay.className = 'sl-overlay';
    overlay.innerHTML =
      '<div class="sl-modal">' + innerHtml +
      '<div class="sl-footer"><button class="btn btn-secondary" id="sl-close">Закрыть</button></div>' +
      '</div>';
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closeDialog();
    });
    document.body.appendChild(overlay);
    document.getElementById('sl-close').addEventListener('click', closeDialog);
    return overlay;
  }

  async function showCertificateDialog(docId, onSigned) {
    console.log('[sign-local] showCertificateDialog called for', docId);
    renderDialog('<h3>Выбор сертификата для подписи</h3><div class="sl-msg"><span class="sl-spinner"></span>Загрузка списка сертификатов…</div>');

    var certs;
    try {
      certs = await listCertificates();
    } catch (e) {
      var msg = (e && e.message) ? e.message : String(e);
      renderDialog('<h3>Ошибка</h3><div class="sl-msg sl-error">' + escapeHtml(msg) + '</div>');
      return;
    }

    if (!certs.length) {
      renderDialog('<h3>Сертификаты не найдены</h3><div class="sl-msg">Проверьте, что КриптоПро CSP установлен и USB-токен (Рутокен) подключён к компьютеру.</div>');
      return;
    }

    var html = '<h3>Выбор сертификата для подписи</h3>';
    html += certs.map(function (c, idx) {
      return '<div class="sl-cert" data-idx="' + idx + '">' +
        '<div class="sl-subj">' + escapeHtml(c.subjectName) + '</div>' +
        '<div class="sl-meta">Издатель: ' + escapeHtml(c.issuerName) + '</div>' +
        '<div class="sl-meta">Действителен: ' + escapeHtml(formatDate(c.validFrom)) + ' — ' + escapeHtml(formatDate(c.validTo)) + '</div>' +
        '</div>';
    }).join('');

    var overlay = renderDialog(html);
    overlay.querySelectorAll('.sl-cert').forEach(function (el) {
      el.addEventListener('click', async function () {
        var idx = parseInt(el.getAttribute('data-idx'), 10);
        var cert = certs[idx];
        renderDialog('<h3>Подписание</h3><div class="sl-msg"><span class="sl-spinner"></span>Ожидание ввода PIN-кода и создание подписи…</div>');
        try {
          var result = await signDocument(docId, cert.thumbprint);
          var signer = result.signer || cert.subjectName;
          renderDialog('<h3>Документ подписан</h3><div class="sl-msg">Подписант: ' + escapeHtml(signer) + '</div>');
          if (typeof onSigned === 'function') onSigned(result);
        } catch (e) {
          var msg = (e && e.message) ? e.message : String(e);
          renderDialog('<h3>Ошибка подписания</h3><div class="sl-msg sl-error">' + escapeHtml(msg) + '</div>');
        }
      });
    });
  }

  console.log('[sign-local] RbSignLocal registered; cadesplugin=', typeof window.cadesplugin);
})();
