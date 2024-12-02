Backend

Create Virtual Environment to manage dependencies.

python3 -m venv env

python -m venv env

On macOS / Linux:

source env/bin/activate


On Windows:

env\Scripts\activate


Install dependencies:

pip install --upgrade pip

pip install -r requirements.txt


Apply Migrations!
python manage.py migrate

Create superUser (optional):
python manage.py createsuperuser


python manage.py runserver


