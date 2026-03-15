from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Profile, SkillTest
from .serializers import ProfileSerializer, SkillTestSerializer
from datetime import datetime


class ProfileDetailView(APIView):
    """Get or update user profile"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get current user profile"""
        try:
            profile = Profile.objects(user_id=request.user.id).first()
            if not profile:
                return Response({
                    'detail': 'Profile not found',
                    'profile_completed': False
                }, status=status.HTTP_404_NOT_FOUND)
            
            serializer = ProfileSerializer(profile)
            return Response({
                **serializer.data,
                'id': str(profile.id),
                'user_id': str(profile.user_id.id)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def post(self, request):
        """Create new profile"""
        try:
            # Check if profile already exists
            existing = Profile.objects(user_id=request.user.id).first()
            if existing:
                return Response({'detail': 'Profile already exists'}, status=status.HTTP_400_BAD_REQUEST)
            
            data = request.data.copy()
            data['user_id'] = request.user.id
            
            serializer = ProfileSerializer(data=data)
            if serializer.is_valid():
                profile = serializer.save(user_id=request.user)
                return Response({
                    'message': 'Profile created successfully',
                    **serializer.data,
                    'id': str(profile.id),
                    'user_id': str(profile.user_id.id),
                    'profile_completed': False
                }, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        """Update user profile"""
        try:
            profile = Profile.objects(user_id=request.user.id).first()
            if not profile:
                return Response({'detail': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
            
            data = request.data.copy()
            # Remove user_id from data if present
            data.pop('user_id', None)
            
            # Mark as completed if bio, skills, and hourly_rate are provided
            if data.get('bio') and data.get('skills') and data.get('hourly_rate'):
                data['profile_completed'] = True
            
            serializer = ProfileSerializer(profile, data=data, partial=True)
            if serializer.is_valid():
                updated_profile = serializer.save()
                return Response({
                    'message': 'Profile updated successfully',
                    **serializer.data,
                    'id': str(updated_profile.id),
                    'user_id': str(updated_profile.user_id.id)
                }, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SkillTestView(APIView):
    """Manage skill tests for freelancers"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, skill=None):
        """Get skill tests for user"""
        try:
            if skill:
                test = SkillTest.objects(user_id=request.user.id, skill=skill).first()
                if not test:
                    return Response({
                        'detail': f'No test found for skill: {skill}',
                        'test_available': True
                    }, status=status.HTTP_404_NOT_FOUND)
                
                serializer = SkillTestSerializer(test)
                return Response({
                    **serializer.data,
                    'id': str(test.id)
                })
            else:
                tests = SkillTest.objects(user_id=request.user.id)
                serializer = SkillTestSerializer(tests, many=True)
                data = [
                    {
                        **item,
                        'id': str(test.id)
                    }
                    for item, test in zip(serializer.data, tests)
                ]
                return Response(data)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def post(self, request):
        """Create or update skill test"""
        try:
            skill = request.data.get('skill')
            score = request.data.get('score')
            
            if not skill or score is None:
                return Response({
                    'detail': 'skill and score are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if test already exists
            test = SkillTest.objects(user_id=request.user.id, skill=skill).first()
            
            if test:
                # Update existing test
                test.score = score
                test.passed = score >= 70  # 70% is passing score
                test.completed_at = datetime.utcnow()
                test.save()
                
                serializer = SkillTestSerializer(test)
                return Response({
                    'message': 'Skill test updated',
                    **serializer.data,
                    'id': str(test.id)
                }, status=status.HTTP_200_OK)
            else:
                # Create new test
                test = SkillTest(
                    user_id=request.user,
                    skill=skill,
                    score=score,
                    passed=score >= 70,
                    completed_at=datetime.utcnow()
                )
                test.save()
                
                serializer = SkillTestSerializer(test)
                return Response({
                    'message': 'Skill test created',
                    **serializer.data,
                    'id': str(test.id)
                }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
