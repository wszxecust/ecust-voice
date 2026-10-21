import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _module(path):
    return ast.parse((ROOT / path).read_text(encoding="utf-8"))


def _function(module, name):
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function not found: {name}")


def _decorator_names(node):
    names = []
    for deco in node.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return names


def _route_methods(node):
    for deco in node.decorator_list:
        if not isinstance(deco, ast.Call):
            continue
        target = deco.func
        if not isinstance(target, ast.Attribute) or target.attr != "route":
            continue
        methods = None
        for kw in deco.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [
                    elt.value
                    for elt in kw.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
        return methods or ["GET"]
    return []


def _calls(node, function_name):
    return any(
        isinstance(item, ast.Call)
        and (
            isinstance(item.func, ast.Name)
            and item.func.id == function_name
        )
        for item in ast.walk(node)
    )


def test_operational_routes_are_admin_only_and_mutations_are_post():
    module = _module("app.py")
    admin_functions = {
        "search_gateway_stats",
        "get_status",
        "start_app",
        "stop_app",
        "test_log",
        "start_forum_monitoring_api",
        "stop_forum_monitoring_api",
        "fetch_models",
        "test_model_connection",
        "get_config",
        "update_config",
        "get_system_status",
        "start_system",
        "shutdown_system",
    }
    for name in admin_functions:
        assert "admin_required" in _decorator_names(_function(module, name)), name

    for name in {
        "start_app",
        "stop_app",
        "start_forum_monitoring_api",
        "stop_forum_monitoring_api",
        "start_system",
        "shutdown_system",
    }:
        methods = _route_methods(_function(module, name))
        assert "POST" in methods and "GET" not in methods, (name, methods)


def test_campus_global_management_routes_are_admin_only():
    module = _module("CampusPulse/blueprint.py")
    admin_functions = {
        "api_status",
        "api_meme_feedback",
        "api_metrics",
        "api_polls",
        "api_poll_close",
        "api_settings",
        "api_collect",
        "api_job",
        "api_analyses",
        "api_analysis",
        "api_review",
        "api_workflows",
        "api_dashboard",
        "api_auto_reports",
        "api_auto_report",
        "api_auto_report_export",
        "api_cost_pricing",
    }
    for name in admin_functions:
        assert "admin_required" in _decorator_names(_function(module, name)), name


def test_report_endpoints_check_research_or_report_ownership():
    module = _module("ReportEngine/flask_interface.py")

    for name in {"get_status", "generate_report", "get_report_log", "clear_log"}:
        assert _calls(_function(module, name), "_can_access_research_task"), name

    for name in {
        "get_progress",
        "stream_task",
        "get_result",
        "get_result_json",
        "download_report",
        "cancel_task",
        "export_markdown",
        "export_pdf",
    }:
        assert _calls(_function(module, name), "_report_task_for_current_account"), name


def test_background_report_trigger_uses_internal_token():
    source = (ROOT / "utils/research_runner.py").read_text(encoding="utf-8")
    assert "X-BettaFish-Internal-Token" in source
    assert "BETTAFISH_INTERNAL_TOKEN" in source


def test_frontend_admin_controls_are_role_gated():
    template = (ROOT / "templates/index.html").read_text(encoding="utf-8")
    pulse = (ROOT / "CampusPulse/templates/pulse.html").read_text(encoding="utf-8")
    js = (ROOT / "static/js/campus-review.js").read_text(encoding="utf-8")
    for html in (template, pulse):
        assert 'data-admin-only' in html
        assert 'hidden' in html
    assert "/api/auth/me" in js
    assert "identity.is_admin" in js



def test_deployment_ports_do_not_bypass_authentication_proxy():
    for relative in ("docker-compose.yml", "../host-deployment/docker-compose.yml"):
        compose = (ROOT / relative).resolve().read_text(encoding="utf-8")
        for port in ("5000", "8501", "8502", "8503"):
            assert f'127.0.0.1:{port}:{port}' in compose, (relative, port)
