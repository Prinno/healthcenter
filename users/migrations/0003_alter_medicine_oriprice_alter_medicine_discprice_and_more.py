# Generated by Django 5.1.3 on 2024-11-19 22:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0002_medicine"),
    ]

    operations = [
        migrations.AlterField(
            model_name="medicine",
            name="OriPrice",
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name="medicine",
            name="discprice",
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name="medicine",
            name="quantity",
            field=models.IntegerField(),
        ),
    ]
