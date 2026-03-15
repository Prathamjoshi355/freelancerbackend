"""
Common utilities and helper functions for the freelancer platform
"""
from datetime import datetime, timedelta


class NotificationHelper:
    """Helper class for creating notifications"""
    @staticmethod
    def create_notification(user, title, message, notification_type, related_id=None):
        """Create a notification for a user"""
        from notifications.models import Notification
        
        notification = Notification(
            user_id=user,
            title=title,
            message=message,
            notification_type=notification_type,
            related_id=related_id
        )
        notification.save()
        return notification
    
    @staticmethod
    def notify_job_posted(client, job):
        """Notify freelancers about new job"""
        from notifications.models import Notification
        from profiles.models import Profile
        
        # Get all freelancers with matching skills
        freelancers = Profile.objects.filter(skills__in=job.required_skills)
        
        for profile in freelancers:
            NotificationHelper.create_notification(
                user=profile.user_id,
                title="New Job Posted",
                message=f"A new job '{job.title}' matches your skills",
                notification_type="job_posted",
                related_id=str(job.id)
            )
    
    @staticmethod
    def notify_proposal_received(client, proposal):
        """Notify client about new proposal"""
        NotificationHelper.create_notification(
            user=client,
            title="New Proposal Received",
            message=f"You received a new proposal for '{proposal.job_id.title}'",
            notification_type="proposal_received",
            related_id=str(proposal.id)
        )
    
    @staticmethod
    def notify_proposal_accepted(freelancer, proposal):
        """Notify freelancer about proposal acceptance"""
        NotificationHelper.create_notification(
            user=freelancer,
            title="Proposal Accepted!",
            message=f"Your proposal for '{proposal.job_id.title}' has been accepted",
            notification_type="proposal_accepted",
            related_id=str(proposal.id)
        )
    
    @staticmethod
    def notify_payment_received(freelancer, transaction):
        """Notify freelancer about payment"""
        NotificationHelper.create_notification(
            user=freelancer,
            title="Payment Received",
            message=f"You received a payment of ${transaction.net_amount}",
            notification_type="payment_received",
            related_id=str(transaction.id)
        )


class PaymentHelper:
    """Helper class for payment operations"""
    
    PLATFORM_FEE = 0.10  # 10%
    PAYMENT_HOLD_DAYS = 7
    
    @staticmethod
    def calculate_fees(amount):
        """Calculate platform fees"""
        fees = amount * PaymentHelper.PLATFORM_FEE
        net_amount = amount - fees
        return fees, net_amount
    
    @staticmethod
    def get_release_date():
        """Get payment release date (7 days from now)"""
        return datetime.utcnow() + timedelta(days=PaymentHelper.PAYMENT_HOLD_DAYS)
    
    @staticmethod
    def get_available_balance(freelancer):
        """Calculate available balance for freelancer"""
        from payments.models import Transaction
        
        released_transactions = Transaction.objects.filter(
            freelancer_id=freelancer,
            is_released=True,
            status='completed'
        )
        
        return sum(t.net_amount for t in released_transactions)


class ValidationHelper:
    """Helper class for validation"""
    
    @staticmethod
    def validate_budget_range(budget_min, budget_max):
        """Validate budget range"""
        if budget_min < 0 or budget_max < 0:
            return False, "Budget must be positive"
        if budget_min > budget_max:
            return False, "Minimum budget cannot exceed maximum budget"
        return True, "Budget is valid"
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_role(role):
        """Validate user role"""
        return role in ['client', 'freelancer']


class SearchHelper:
    """Helper class for search operations"""
    
    @staticmethod
    def search_jobs(filters):
        """Search jobs with filters"""
        from jobs.models import Job
        
        jobs = Job.objects.filter(status='open')
        
        if 'category' in filters:
            jobs = jobs.filter(category=filters['category'])
        
        if 'experience_level' in filters:
            jobs = jobs.filter(experience_level=filters['experience_level'])
        
        if 'min_budget' in filters:
            jobs = jobs.filter(budget_min__gte=float(filters['min_budget']))
        
        if 'max_budget' in filters:
            jobs = jobs.filter(budget_max__lte=float(filters['max_budget']))
        
        if 'skills' in filters:
            jobs = jobs.filter(required_skills__in=filters['skills'])
        
        return jobs
    
    @staticmethod
    def search_freelancers(filters):
        """Search freelancers with filters"""
        from profiles.models import Profile
        
        profiles = Profile.objects.all()
        
        if 'skill' in filters:
            profiles = profiles.filter(skills__contains=filters['skill'])
        
        if 'min_hourly_rate' in filters:
            profiles = profiles.filter(hourly_rate__gte=float(filters['min_hourly_rate']))
        
        if 'max_hourly_rate' in filters:
            profiles = profiles.filter(hourly_rate__lte=float(filters['max_hourly_rate']))
        
        if 'min_rating' in filters:
            profiles = profiles.filter(rating__gte=float(filters['min_rating']))
        
        return profiles.order_by('-rating')
