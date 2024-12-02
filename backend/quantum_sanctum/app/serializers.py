from rest_framework import serializers
from .models import Task

class TaskSerializer(serializers.ModelSerializer):
    class Initiate:
        model = Task
        fields = ['client_public_key']