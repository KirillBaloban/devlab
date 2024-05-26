import random
from flask import Flask, render_template, request
from faker import Faker
from flask import make_response
fake = Faker()

app = Flask(__name__)
'''all_requests = []'''

images_ids = ['7d4e9175-95ea-4c5f-8be5-92a6b708bb3c',
              '2d2ab7df-cdbc-48a8-a936-35bba702def5',
              '6e12f3de-d5fd-4ebb-855b-8cbc485278b7',
              'afc2cfe7-5cac-4b80-9b9a-d5c65ef0c728',
              'cab5b7f2-774e-4884-a200-0c0180fa777f']


def generate_comments(replies=True):
    comments = []
    for i in range(random.randint(1, 3)):
        comment = {
            'author': fake.name(),
            'text': fake.text()
        }
        if replies:
            comment['replies'] = generate_comments(replies=False)
        comments.append(comment)
    return comments


def generate_post(i):
    return {
        'title': 'Заголовок поста',
        'text': fake.paragraph(nb_sentences=100),
        'author': fake.name(),
        'date': fake.date_time_between(start_date='-2y', end_date='now'),
        'image_id': f'{images_ids[i]}.jpg',
        'comments': generate_comments()
    }


posts_list = sorted([generate_post(i) for i in range(5)], key=lambda p: p['date'], reverse=True)


def validate_phone_number(phone_number):
    # Убрать все символы, кроме цифр
    cleaned_phone_number = ''.join(filter(str.isdigit, phone_number))

    # Проверить длину номера
    if len(cleaned_phone_number) not in [10, 11]:
        return {'success': False, 'message': 'Недопустимый ввод. Неверное количество цифр.'}

    # Проверить на наличие недопустимых символов
    allowed_characters = set('0123456789()+-. ')
    if not all(char in allowed_characters for char in phone_number):
        return {'success': False, 'message': "Недопустимый ввод. В номере телефона встречаются недопустимые символы."}

    # Преобразовать номер к формату 8-***-***--
    if len(cleaned_phone_number) == 11:
        cleaned_phone_number = cleaned_phone_number[1:]
    formatted_phone_number = f'8-{cleaned_phone_number[:3]}-{cleaned_phone_number[3:6]}-{cleaned_phone_number[6:]}'

    return {'success': True, 'message': formatted_phone_number}

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/posts')
def posts():
    return render_template('posts.html', title='Посты', posts=posts_list)


@app.route('/posts/<int:index>', methods=['GET', 'POST'])
def post(index):
    if request.method == 'POST':
        for elem in request.form:
            content = request.form[elem]
            if elem.startswith('reply_to_'):
                comment_index = int(elem.replace('reply_to_', '')) - 1
                posts_list[index]['comments'][comment_index]['replies'].append({
                    'author': 'Admin',
                    'text': content
                })
            else:
                content = request.form['comment']
                posts_list[index]['comments'].append({
                    'author': 'Admin',
                    'text': content,
                    'replies': []
                })

    p = posts_list[index]
    return render_template(
        'post.html',
        title=p['title'],
        index=index,
        post=p
    )


@app.route('/about')
def about():
    return render_template('about.html', title='Об авторе')


@app.route('/error_form', methods=['GET', 'POST'])
def error_form():
    result = {'message': None}
    phone_number = None

    if request.method == 'POST':
        phone_number = request.form['phone_number']
        result = validate_phone_number(phone_number)
        if result['success']:
            return render_template('success.html', phone_number=result['message'])
    return render_template('error_form.html', error=result['message'], phone_number=phone_number)
'''
@app.route('/all_requests')
def show_all_requests():
    return render_template('all_requests.html', all_requests=all_requests)

# Регистрируем обработчик для всех маршрутов
@app.before_request
def log_request_info():
    request_data = {
        'url': request.url,
        'method': request.method,
        'args': request.args.to_dict(),
        'form': request.form.to_dict(),
        'headers': dict(request.headers),
        'cookies': request.cookies
    }
    all_requests.append(request_data)
'''
@app.route('/display_info', methods=['GET', 'POST'])
def display_info():
    # Получаем параметры URL
    url_params = request.args.to_dict()

    # Получаем заголовки запроса
    headers = request.headers

    # Получаем значения из cookie
    cookies = request.cookies

    # Обрабатываем установку и удаление cookie
    if request.method == 'POST':
        cookie_name = request.form.get('cookie_name')
        cookie_value = request.form.get('cookie_value')

        if cookie_name and cookie_value:
            response = make_response(render_template('display_info.html', url_params=url_params, headers=headers, cookies=cookies))
            response.set_cookie(cookie_name, cookie_value)
            return response

        cookie_to_delete = request.form.get('cookie_to_delete')
        if cookie_to_delete in cookies:
            response = make_response(render_template('display_info.html', url_params=url_params, headers=headers, cookies=cookies))
            response.set_cookie(cookie_to_delete, expires=0)
            return response

    return render_template('display_info.html', url_params=url_params, headers=headers, cookies=cookies)

if __name__ == '__main__':
    app.run(debug=True)
