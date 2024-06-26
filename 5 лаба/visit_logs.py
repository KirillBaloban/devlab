import csv
from functools import wraps
from io import StringIO, BytesIO

from flask import Blueprint, render_template, request, send_file
from flask_login import current_user, login_required

from models import db, VisitLogs
from functions import check_rights

visit_logs_bp = Blueprint(
    'visit_logs',
    __name__,
    template_folder='templates/visits'
)

def add_visit_log(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            visit_log = VisitLogs(
                user=current_user.get_full_name(),
                page=request.path
            )
        else:
            visit_log = VisitLogs(
                user='Неаутентифицированный пользователь',
                page=request.path
            )
        db.session.add(visit_log)
        db.session.commit()
        return f(*args, **kwargs)
    return decorated_function


@visit_logs_bp.route('/')
@login_required
def index():
    if current_user.role.name == 'admin':
        visit_logs = db.session.query(VisitLogs).order_by(db.desc('creation_date'))
    else:
        visit_logs = db.session.query(VisitLogs).where(
            VisitLogs.user == current_user.get_full_name()
        ).order_by(db.desc('creation_date'))
    pagination = db.paginate(visit_logs)
    visit_logs = pagination.items

    return render_template(
        'visits_index.html',
        visit_logs=visit_logs,
        pagination=pagination
    )


@visit_logs_bp.route('/pages')
@login_required
@check_rights
def pages():
    page_visits = db.session.query(
        VisitLogs.page, db.func.count(VisitLogs.page).label('visits')
    ).group_by(VisitLogs.page).order_by(db.desc('visits')).all()
    return render_template('visits_pages.html', page_visits=page_visits)


@visit_logs_bp.route('/pages/export')
@login_required
@check_rights
def export_pages():
    page_visits = db.session.query(
        VisitLogs.page, db.func.count(VisitLogs.page).label('visits')
    ).group_by(VisitLogs.page).order_by(db.desc('visits')).all()

    proxy = StringIO()
    cw = csv.writer(proxy)

    cw.writerow(['index', 'page', 'count'])
    for i, row in enumerate(page_visits, start=1):
        cw.writerow([i, row.page, row.visits])

    mem = BytesIO()
    mem.write(proxy.getvalue().encode())
    mem.seek(0)
    proxy.close()

    return send_file(
        mem,
        mimetype='text/csv'
    )


@visit_logs_bp.route('/users')
@login_required
@check_rights
def users():
    user_visits = db.session.query(
       VisitLogs.user, db.func.count(VisitLogs.user).label('visits')
    ).group_by(VisitLogs.user).order_by(db.desc('visits')).all()

    return render_template('visits_users.html', user_visits=user_visits)


@visit_logs_bp.route('/users/export')
@login_required
@check_rights
def export_users():
    user_visits = db.session.query(
        VisitLogs.user, db.func.count(VisitLogs.user).label('visits')
    ).group_by(VisitLogs.user).order_by(db.desc('visits')).all()

    proxy = StringIO()
    cw = csv.writer(proxy)

    cw.writerow(['index', 'user', 'count'])
    for i, row in enumerate(user_visits, start=1):
        cw.writerow([i, row.user, row.visits])

    mem = BytesIO()
    mem.write(proxy.getvalue().encode())
    mem.seek(0)
    proxy.close()

    return send_file(
        mem,
        mimetype='text/csv'
    )
