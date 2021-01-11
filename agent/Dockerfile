FROM registry.redhat.io/rhel8/python-38

COPY agent.py requirements.txt logo.py .

RUN pip install -r requirements.txt

ENTRYPOINT ["python","agent.py"]
