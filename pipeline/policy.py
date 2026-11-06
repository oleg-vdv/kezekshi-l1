# coding: utf-8
"""Маршрутизация: что система закрывает сама, что уходит на L2.

Цель - меньше ложных эскалаций (шума на L2), не теряя атаки. Ключ к этому -
памятка правил (`src/rulebook.py`): это разметка аналитика, какой тип алерта на
каком правиле обычно шум, с учётом контекста (путь файла, источник входа и т.п.).
Ей и доверяем закрывать известный шум.

Режим задаётся KEZEKSHI_AUTOCLOSE:
  rulebook (по умолчанию) - закрывать известный шум по памятке, с сетью
      безопасности: если модель уверенно видит инцидент, всё равно на L2;
  assist   - фаза внедрения «ассист»: сам закрывает ТОЛЬКО детерминированный
      шум из белого списка (fast-path), а всё, что дошло до модели, уходит
      человеку с черновой карточкой. Модель не закрывает НИЧЕГО - только
      готовит разбор. Нулевой риск: ни одной эскалации система не гасит сама;
  strict   - закрывать только когда И модель, И памятка согласны «не атака»
      (меньше авто-закрытий, больше шума на L2);
  off      - ничего не закрывать, только сортировать и писать карточку.

Атаку (памятка suspicious/incident) система не закрывает ни в одном режиме.
Инъекция в логах и ответ, не прошедший валидатор, всегда уходят на L2.

Операционный шум (`rulebook.hard_benign`): на явном белом списке высокочастотных
шумовых правил (ротация реестра/файрвола, ошибки приложений, события самого
Wazuh, штатные Linux-события, rootcheck-замечания и т.п.) памятка авторитетнее
модели - такой алерт закрывается, даже если модель переоценила тяжесть
(incident). Это снимает ложные эскалации, где модель вживую фантазирует на
незнакомых ей типах правил. Контекст памятки при этом эскалирует опасные
под-случаи (autorun-ключи, rootkit, критичные пути, защитные службы) - они дают
suspicious и в белый список не попадают. Риск: атака, которая фонит только таким
шумовым правилом в "безопасном" контексте, может закрыться; его снижают
контекстные условия и выбор режима `strict`/`off`. Вход/подбор/новые
пользователи и службы в белый список НЕ входят - там сеть безопасности по модели
сохраняется.
"""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from rulebook import label, R, hard_benign  # noqa: E402

NON_ESCALATING = {"false_positive", "benign_true_positive"}
MODE = os.environ.get("KEZEKSHI_AUTOCLOSE", "rulebook")


def fast_decide(case, flags, ev):
    """Исход, НЕ зависящий от модели -> решаем без её вызова (иначе None).

    Таких случаев два, и в обоих ответ модели на решение не влияет:
      - инъекция в логах: недоверенный ввод, разбор без модели, всегда на L2;
      - операционный шум из белого списка (`hard_benign`): памятка авторитетнее
        модели и закрывает алерт даже при вердикте модели incident - значит
        вызывать модель незачем.
    На реальном потоке стенда это ~95 % алертов: модель остаётся только для
    неоднозначного хвоста. Инъекция обрабатывается во всех режимах; авто-закрытие
    по белому списку - в режимах rulebook и assist (strict/off требуют модель).
    """
    rid = str(case["rule_id"])
    rb_verdict, rb_mitre, rb_why, rb_checks = label(rid, ev, case["level"])

    def out(action, reason):
        return {"action": action, "model_verdict": None, "rule_verdict": rb_verdict,
                "rule_known": rid in R, "mode": MODE, "reason": reason,
                "rule_why": rb_why, "rule_checks": rb_checks, "model_used": False}

    if "injection" in flags:
        return out("to_L2", "в логах текст, похожий на инструкцию модели: разбор без модели, на L2")
    if MODE in ("rulebook", "assist") and hard_benign(rid, ev, case["level"]):
        return out("auto_close", f"памятка: операционный шум (правило {rid}) - закрыто без вызова модели")
    return None


def decide(case, ans, errs, flags):
    """-> dict: action in {auto_close, to_L2}, с причиной и данными для аудита.

    Вызывается только для хвоста, которому нужна модель (см. fast_decide)."""
    ev = {e["field"]: e["value"] for e in case["evidence"]}
    rid = str(case["rule_id"])
    known = rid in R
    rb_verdict, rb_mitre, rb_why, rb_checks = label(rid, ev, case["level"])
    model_v = (ans or {}).get("verdict")

    def out(action, reason):
        return {"action": action, "model_verdict": model_v, "rule_verdict": rb_verdict,
                "rule_known": known, "mode": MODE, "reason": reason,
                "rule_why": rb_why, "rule_checks": rb_checks, "model_used": True}

    # 1. недоверенный ввод и брак ответа - всегда человеку
    if "injection" in flags:
        return out("to_L2", "в логах текст, похожий на инструкцию модели: разбор без модели, на L2")
    if errs:
        return out("to_L2", "ответ модели не прошёл валидатор: " + "; ".join(errs[:3]))

    # 1b. режим ассист: модель НИЧЕГО не закрывает - всё, что дошло до неё,
    #     уходит человеку с черновой карточкой. Сам закрывается только шум из
    #     белого списка (в fast_decide до вызова модели).
    if MODE == "assist":
        return out("to_L2", f"ассист: карточка модели на разбор L2 (модель: {model_v or '-'}, памятка: {rb_verdict})")

    # 2. известный шум по памятке - закрываем сами (режим rulebook)
    if MODE == "rulebook" and known and rb_verdict in NON_ESCALATING:
        if model_v == "incident_candidate" and not hard_benign(rid, ev, case["level"]):
            # сеть безопасности: модель уверенно против, и правило не из белого
            # списка операционного шума - отдаём человеку
            return out("to_L2", "памятка: известный шум, но модель видит инцидент - на проверку L2")
        reason = f"памятка: правило {rid} - известный шум ({rb_verdict})"
        if model_v == "incident_candidate":
            reason = f"памятка: операционный шум (правило {rid}), закрыто по памятке несмотря на вердикт модели incident"
        return out("auto_close", reason)

    # 3. высокий уровень не-шумового правила - человеку
    if "level>=12" in flags:
        return out("to_L2", f"правило уровня {case['level']} (>=12): на L2")

    # 4. строгий режим и неизвестное правило: закрываем только при согласии модели и памятки
    if model_v in NON_ESCALATING and rb_verdict in NON_ESCALATING and MODE != "off":
        return out("auto_close", "модель и памятка согласны: не атака")
    if model_v is None:
        return out("to_L2", "модель не вернула вердикт")
    return out("to_L2", f"требует внимания L2 (модель: {model_v}, памятка: {rb_verdict})")
