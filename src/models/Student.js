const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
  // Basic Information (Directory Information - FERPA)
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  schoolId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  gradeLevel: {
    type: String,
    required: true,
    enum: ['K', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', 'Post-Secondary']
  },
  
  // Current Classes (Directory Information - FERPA)
  currentClasses: [{
    classId: String,
    className: String,
    teacherId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    semester: String,
    year: Number
  }],
  
  // Educational Records (Protected - FERPA)
  iepDocuments: [{
    documentType: {
      type: String,
      enum: ['IEP', '504_Plan', 'Evaluation_Report', 'Progress_Report', 'Transition_Plan']
    },
    documentName: String,
    filePath: String,
    uploadDate: Date,
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  
  disabilityClassification: {
    type: String,
    enum: [
      'Autism',
      'Deaf-Blindness',
      'Deafness',
      'Emotional Disturbance',
      'Hearing Impairment',
      'Intellectual Disability',
      'Multiple Disabilities',
      'Orthopedic Impairment',
      'Other Health Impairment',
      'Specific Learning Disability',
      'Speech or Language Impairment',
      'Traumatic Brain Injury',
      'Visual Impairment',
      'None'
    ]
  },
  
  // Parent/Guardian Information (Educational Record - FERPA)
  parentContacts: [{
    parentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    relationship: {
      type: String,
      enum: ['Mother', 'Father', 'Guardian', 'Step-Parent', 'Other']
    },
    isPrimary: {
      type: Boolean,
      default: false
    },
    hasCustody: {
      type: Boolean,
      default: true
    },
    emergencyContact: {
      type: Boolean,
      default: false
    }
  }],
  
  // Evaluations (Educational Record - FERPA)
  evaluations: [{
    evaluationType: {
      type: String,
      enum: ['Initial', 'Re-evaluation', 'Exit', 'Other']
    },
    evaluationDate: Date,
    evaluator: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    results: String,
    recommendations: String,
    documents: [String] // File paths
  }],
  
  // Progress Monitoring (Educational Record - FERPA)
  progressMonitoring: [{
    date: Date,
    area: {
      type: String,
      enum: ['Academic', 'Behavioral', 'Social', 'Communication', 'Motor', 'Other']
    },
    goal: String,
    currentLevel: String,
    targetLevel: String,
    progress: {
      type: String,
      enum: ['Exceeding', 'Meeting', 'Approaching', 'Below']
    },
    notes: String,
    recordedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  
  // Additional FERPA-compliant fields
  emergencyContacts: [{
    name: String,
    relationship: String,
    phone: String,
    email: String,
    isPrimary: {
      type: Boolean,
      default: false
    }
  }],
  
  medicalAlerts: [{
    alertType: {
      type: String,
      enum: ['Allergy', 'Medication', 'Medical_Condition', 'Dietary_Restriction', 'Other']
    },
    description: String,
    severity: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical']
    },
    instructions: String
  }],
  
  transportationInfo: {
    busRoute: String,
    pickupLocation: String,
    dropoffLocation: String,
    authorizedPickupPersons: [String],
    specialTransportationNeeds: String
  },
  
  attendance: [{
    date: Date,
    status: {
      type: String,
      enum: ['Present', 'Absent', 'Tardy', 'Excused_Absence']
    },
    notes: String
  }],
  
  // 504 Plans (if applicable)
  section504Plans: [{
    planType: String,
    accommodations: [String],
    effectiveDate: Date,
    reviewDate: Date,
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  
  // Language Proficiency
  languageProficiency: {
    primaryLanguage: String,
    englishProficiency: {
      type: String,
      enum: ['Native', 'Fluent', 'Intermediate', 'Beginner', 'Non-English_Speaker']
    },
    eslStatus: {
      type: String,
      enum: ['Not_ESL', 'ESL_Student', 'Former_ESL', 'Bilingual']
    }
  },
  
  // Gifted/Talented Programs
  giftedPrograms: [{
    programName: String,
    startDate: Date,
    endDate: Date,
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  
  // Behavioral Interventions
  behavioralInterventions: [{
    interventionType: String,
    startDate: Date,
    endDate: Date,
    description: String,
    effectiveness: {
      type: String,
      enum: ['Very_Effective', 'Effective', 'Somewhat_Effective', 'Not_Effective']
    },
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  
  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
studentSchema.index({ user: 1 });
studentSchema.index({ schoolId: 1 });
studentSchema.index({ gradeLevel: 1 });
studentSchema.index({ 'currentClasses.teacherId': 1 });
studentSchema.index({ 'parentContacts.parentId': 1 });

// Virtual for active IEP
studentSchema.virtual('activeIEP').get(function() {
  return this.iepDocuments.find(doc => 
    doc.documentType === 'IEP' && doc.isActive
  );
});

// Virtual for primary parent
studentSchema.virtual('primaryParent').get(function() {
  return this.parentContacts.find(contact => contact.isPrimary);
});

// Pre-save middleware
studentSchema.pre('save', function(next) {
  // Ensure only one primary parent
  if (this.parentContacts.length > 0) {
    const primaryParents = this.parentContacts.filter(contact => contact.isPrimary);
    if (primaryParents.length > 1) {
      return next(new Error('Only one parent can be marked as primary'));
    }
  }
  next();
});

// Instance methods
studentSchema.methods.addProgressEntry = function(entry) {
  this.progressMonitoring.push(entry);
  return this.save();
};

studentSchema.methods.getRecentProgress = function(limit = 10) {
  return this.progressMonitoring
    .sort((a, b) => b.date - a.date)
    .slice(0, limit);
};

studentSchema.methods.hasActiveIEP = function() {
  return this.iepDocuments.some(doc => 
    doc.documentType === 'IEP' && doc.isActive
  );
};

// Static methods
studentSchema.statics.findBySchoolId = function(schoolId) {
  return this.findOne({ schoolId }).populate('user');
};

studentSchema.statics.findByTeacher = function(teacherId) {
  return this.find({ 'currentClasses.teacherId': teacherId }).populate('user');
};

studentSchema.statics.findByParent = function(parentId) {
  return this.find({ 'parentContacts.parentId': parentId }).populate('user');
};

module.exports = mongoose.model('Student', studentSchema);
