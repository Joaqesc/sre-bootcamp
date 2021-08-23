FROM python:3-alpine
ADD . /sre-bootcamp
WORKDIR /sre-bootcamp
RUN pip install -r requirements.txt
ENV DB_HOST=bootcamp-tht.sre.wize.mx DB_USER=secret DB_PASSWORD=noPow3r DB_NAME=bootcamp_tht JWT_SECRET=my2w7wjd7yXF64FIADfJxNs1oupTGAuW
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=8000"]
