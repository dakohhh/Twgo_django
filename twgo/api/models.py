from django.db import models
from django.contrib.auth import models as auth_models


class UserManager(auth_models.BaseUserManager):
    def create_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        password: str = None,
        phone_number: str = None,
        nationality: str = None,
        gender: str = None,
        is_staff=False,
        is_superuser=False,
    ) -> "User":
        if not email:
            raise ValueError("User must have an email")
        if not first_name:
            raise ValueError("User must have a first name")
        if not last_name:
            raise ValueError("User must have a last name")

        user = self.model(email=self.normalize_email(email))
        user.first_name = first_name
        user.last_name = last_name
        user.phone_number = phone_number
        user.nationality = nationality
        user.gender = gender
        user.set_password(password)
        user.is_active = True
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.save()

        return user

    def create_superuser(
        self, first_name: str, last_name: str, email: str, password: str,
        phone_number: str = None,
        nationality: str = None,
        gender: str = None,
    ) -> "User":
        user = self.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            phone_number=phone_number,
            nationality=nationality,
            gender=gender,
            is_staff=True,
            is_superuser=True,
        )
        user.save()

        return user


class User(auth_models.AbstractUser):
    first_name = models.CharField(verbose_name="First Name", max_length=255)
    last_name = models.CharField(verbose_name="Last Name", max_length=255)
    email = models.EmailField(verbose_name="Email",
                              max_length=255, unique=True)
    password = models.CharField(max_length=255)
    phone_number = models.CharField(verbose_name="Phone Number", max_length=20)
    nationality = models.CharField(verbose_name="Nationality", max_length=100)
    gender = models.CharField(verbose_name="Gender", max_length=10)

    username = None

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name",
                       "phone_number", "nationality", "gender"]


class Project(models.Model):
    STATUS_CHOICES = (
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('pending', 'Pending'),
    )

    title = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    category = models.CharField(max_length=255)
    budget = models.CharField(max_length=255)
    service_type = models.CharField(max_length=255)
    delivery_date = models.CharField(max_length=255)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='projects_as_user')
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default='pending')

    def save(self, *args, **kwargs):
        is_new_project = self._state.adding  # Check if it's a new project

        super().save(*args, **kwargs)  # Call the original save method

        if is_new_project:
            admins = User.objects.filter(
                is_staff=True)  # Get all admin users
            for admin in admins:
                notification = Notifications(
                    user=admin, message='New project created', details=f'A new project "{self.title}" has been created.')
                notification.save()


class Funds(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    total_balance = models.DecimalField(
        max_digits=10, decimal_places=2, default=0)
    deposit = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    referral_bonus = models.DecimalField(
        max_digits=10, decimal_places=2, default=0)


class Notifications(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    details = models.CharField(max_length=1000)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.message


class Conversation(models.Model):
    participants = models.ManyToManyField(User, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        participant_names = ', '.join(
            [str(participant) for participant in self.participants.all()])
        return f"Conversation with {participant_names}"


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content
