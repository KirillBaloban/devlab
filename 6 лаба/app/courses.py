from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import select, desc, update, and_
from sqlalchemy.exc import IntegrityError
from models import db, Course, Category, User, Review
from tools import CoursesFilter, ImageSaver, ReviewsSort

bp = Blueprint('courses', __name__, url_prefix='/courses')

COURSE_PARAMS = [
    'author_id', 'name', 'category_id', 'short_desc', 'full_desc'
]


def params():
    return {p: request.form.get(p) or None for p in COURSE_PARAMS}


def search_params():
    return {
        'name': request.args.get('name'),
        'category_ids': [x for x in request.args.getlist('category_ids') if x],
    }


@bp.route('/')
def index():
    courses = CoursesFilter(**search_params()).perform()
    pagination = db.paginate(courses)
    courses = pagination.items
    categories = db.session.execute(db.select(Category)).scalars()
    return render_template('courses/index.html',
                           courses=courses,
                           categories=categories,
                           pagination=pagination,
                           search_params=search_params())


@bp.route('/new')
@login_required
def new():
    course = Course()
    categories = db.session.execute(db.select(Category)).scalars()
    users = db.session.execute(db.select(User)).scalars()
    return render_template('courses/new.html',
                           categories=categories,
                           users=users,
                           course=course)


@bp.route('/create', methods=['POST'])
@login_required
def create():
    f = request.files.get('background_img')
    img = None
    course = Course()
    try:
        if f and f.filename:
            img = ImageSaver(f).save()

        image_id = img.id if img else None
        course = Course(**params(), background_image_id=image_id)
        db.session.add(course)
        db.session.commit()
    except IntegrityError as err:
        flash(f'Возникла ошибка при записи данных в БД. Проверьте корректность введённых данных. ({err})', 'danger')
        db.session.rollback()
        categories = db.session.execute(db.select(Category)).scalars()
        users = db.session.execute(db.select(User)).scalars()
        return render_template('courses/new.html',
                               categories=categories,
                               users=users,
                               course=course)

    flash(f'Курс {course.name} был успешно добавлен!', 'success')

    return redirect(url_for('courses.index'))


@bp.route('/<int:course_id>')
def show(course_id):
    course = db.get_or_404(Course, course_id)

    reviews = db.session.execute(
        select(Review)
        .where(Review.course_id == course.id)
        .order_by(desc(Review.created_at))
        .limit(5)
    ).scalars().all()

    current_user_review = db.session.execute(
        select(Review)
        .filter(
            and_(
                Review.course_id == course.id,
                Review.user_id == current_user.id
            )
        )
    ).one_or_none()
    if current_user_review:
        current_user_review = current_user_review[0]

    return render_template(
        'courses/show.html',
        course=course,
        reviews=reviews,
        current_user_review=current_user_review
    )


@bp.route('/<int:course_id>/reviews')
def course_reviews(course_id):
    course = db.get_or_404(Course, course_id)

    sort_by = request.args.get('reviews-sort-by')
    reviews = ReviewsSort(
        course_id=course.id,
        sort_by=sort_by
    ).perform()
    pagination = db.paginate(reviews)
    reviews = pagination.items

    current_user_review = db.session.execute(
        select(Review)
        .filter(
            and_(
                Review.course_id == course.id,
                Review.user_id == current_user.id
            )
        )
    ).one_or_none()
    if current_user_review:
        current_user_review = current_user_review[0]

    return render_template(
        'courses/reviews.html',
        pagination=pagination,
        course=course,
        reviews=reviews,
        current_user_review=current_user_review,
        sort_by={
            "sort_by": sort_by,
            "course_id": course.id
        }
    )


@bp.route('/<int:course_id>/reviews/create', methods=['POST'])
def create_review(course_id):
    course = db.get_or_404(Course, course_id)

    reviews = db.session.execute(
        select(Review)
        .where(Review.course_id == course.id)
        .order_by(desc(Review.created_at))
    ).scalars().all()

    for review in reviews:
        if review.user_id == current_user.id:
            flash(f'У вас уже есть отзыв для этого курса.', 'warning')
            return render_template('courses/show.html', course=course, reviews=reviews[:5])
    try:
        review = Review(
            rating=int(request.form.get('rating')),
            text=request.form.get('text'),
            user_id=current_user.id,
            course_id=course_id
        )
        db.session.add(review)

        course.rating_sum += int(review.rating)
        course.rating_num += 1
        db.session.commit()
    except IntegrityError as err:
        flash(f'Возникла ошибка при записи данных в БД. Проверьте корректность введённых данных. ({err})', 'danger')

        db.session.rollback()

        return render_template('courses/show.html', course=course, reviews=reviews[:5])

    flash(f'Отзыв для курса {course.name} был успешно добавлен!', 'success')
    return redirect(url_for('courses.index'))
