"""Auto-create UserProfile when a new Django User is created."""


def create_user_profile(sender, instance, created, **kwargs):
    if created:
        from dashboard.models import UserProfile
        UserProfile.objects.get_or_create(user=instance)
