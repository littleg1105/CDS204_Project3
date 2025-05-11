ls eshop/migrations/
python manage.py makemigrations eshop
python manage.py migrate


python manage.py runserver

python manage.py runserver_plus --cert-file=certificates/cert.pem --key-file=certificates/key.pem