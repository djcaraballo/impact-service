const { gql } = require('apollo-server-express');

const typeDefs = gql`
  # User Types
  type User {
    id: ID!
    email: String!
    firstName: String!
    lastName: String!
    fullName: String!
    role: UserRole!
    isActive: Boolean!
    isEmailVerified: Boolean!
    phone: String
    ssoProvider: SSOProvider
    lastLoginAt: String
    ferpaConsent: Boolean!
    ferpaConsentDate: String
    createdAt: String!
    updatedAt: String!
  }

  type Student {
    id: ID!
    user: User!
    schoolId: String!
    gradeLevel: String!
    currentClasses: [Class!]!
    iepDocuments: [IEPDocument!]!
    disabilityClassification: String
    parentContacts: [ParentContact!]!
    evaluations: [Evaluation!]!
    progressMonitoring: [ProgressEntry!]!
    emergencyContacts: [EmergencyContact!]!
    medicalAlerts: [MedicalAlert!]!
    transportationInfo: TransportationInfo
    attendance: [AttendanceRecord!]!
    section504Plans: [Section504Plan!]!
    languageProficiency: LanguageProficiency
    giftedPrograms: [GiftedProgram!]!
    behavioralInterventions: [BehavioralIntervention!]!
    activeIEP: IEPDocument
    primaryParent: ParentContact
    createdAt: String!
    updatedAt: String!
  }

  # Supporting Types
  type Class {
    classId: String!
    className: String!
    teacherId: ID!
    teacher: User
    semester: String!
    year: Int!
  }

  type IEPDocument {
    id: ID!
    documentType: IEPDocumentType!
    documentName: String!
    filePath: String!
    uploadDate: String!
    uploadedBy: ID!
    uploadedByUser: User
    isActive: Boolean!
  }

  type ParentContact {
    id: ID!
    parentId: ID!
    parent: User
    relationship: ParentRelationship!
    isPrimary: Boolean!
    hasCustody: Boolean!
    emergencyContact: Boolean!
  }

  type Evaluation {
    id: ID!
    evaluationType: EvaluationType!
    evaluationDate: String!
    evaluator: ID!
    evaluatorUser: User
    results: String!
    recommendations: String!
    documents: [String!]!
  }

  type ProgressEntry {
    id: ID!
    date: String!
    area: ProgressArea!
    goal: String!
    currentLevel: String!
    targetLevel: String!
    progress: ProgressLevel!
    notes: String
    recordedBy: ID!
    recordedByUser: User
  }

  type EmergencyContact {
    id: ID!
    name: String!
    relationship: String!
    phone: String!
    email: String
    isPrimary: Boolean!
  }

  type MedicalAlert {
    id: ID!
    alertType: MedicalAlertType!
    description: String!
    severity: AlertSeverity!
    instructions: String
  }

  type TransportationInfo {
    busRoute: String
    pickupLocation: String
    dropoffLocation: String
    authorizedPickupPersons: [String!]!
    specialTransportationNeeds: String
  }

  type AttendanceRecord {
    id: ID!
    date: String!
    status: AttendanceStatus!
    notes: String
  }

  type Section504Plan {
    id: ID!
    planType: String!
    accommodations: [String!]!
    effectiveDate: String!
    reviewDate: String!
    isActive: Boolean!
  }

  type LanguageProficiency {
    primaryLanguage: String!
    englishProficiency: EnglishProficiency!
    eslStatus: ESLStatus!
  }

  type GiftedProgram {
    id: ID!
    programName: String!
    startDate: String!
    endDate: String
    isActive: Boolean!
  }

  type BehavioralIntervention {
    id: ID!
    interventionType: String!
    startDate: String!
    endDate: String
    description: String!
    effectiveness: InterventionEffectiveness!
    isActive: Boolean!
  }

  # Authentication Types
  type AuthTokens {
    accessToken: String!
    refreshToken: String!
  }

  type AuthResponse {
    user: User!
    tokens: AuthTokens!
    message: String!
  }

  type SSOProvider {
    name: String!
    displayName: String!
    authUrl: String!
  }

  # Enums
  enum UserRole {
    ADMIN
    TEACHER
    SERVICE_PROVIDER
    PARENT
    STUDENT
  }

  enum SSOProvider {
    GOOGLE
    SAML
  }

  enum IEPDocumentType {
    IEP
    PLAN_504
    EVALUATION_REPORT
    PROGRESS_REPORT
    TRANSITION_PLAN
  }

  enum ParentRelationship {
    MOTHER
    FATHER
    GUARDIAN
    STEP_PARENT
    OTHER
  }

  enum EvaluationType {
    INITIAL
    RE_EVALUATION
    EXIT
    OTHER
  }

  enum ProgressArea {
    ACADEMIC
    BEHAVIORAL
    SOCIAL
    COMMUNICATION
    MOTOR
    OTHER
  }

  enum ProgressLevel {
    EXCEEDING
    MEETING
    APPROACHING
    BELOW
  }

  enum MedicalAlertType {
    ALLERGY
    MEDICATION
    MEDICAL_CONDITION
    DIETARY_RESTRICTION
    OTHER
  }

  enum AlertSeverity {
    LOW
    MEDIUM
    HIGH
    CRITICAL
  }

  enum AttendanceStatus {
    PRESENT
    ABSENT
    TARDY
    EXCUSED_ABSENCE
  }

  enum EnglishProficiency {
    NATIVE
    FLUENT
    INTERMEDIATE
    BEGINNER
    NON_ENGLISH_SPEAKER
  }

  enum ESLStatus {
    NOT_ESL
    ESL_STUDENT
    FORMER_ESL
    BILINGUAL
  }

  enum InterventionEffectiveness {
    VERY_EFFECTIVE
    EFFECTIVE
    SOMEWHAT_EFFECTIVE
    NOT_EFFECTIVE
  }

  # Input Types
  input RegisterInput {
    email: String!
    password: String!
    firstName: String!
    lastName: String!
    role: UserRole
    phone: String
  }

  input LoginInput {
    email: String!
    password: String!
  }

  input ChangePasswordInput {
    currentPassword: String!
    newPassword: String!
  }

  input UpdateProfileInput {
    firstName: String
    lastName: String
    phone: String
  }

  input CreateStudentInput {
    userId: ID!
    schoolId: String!
    gradeLevel: String!
  }

  input UpdateStudentInput {
    schoolId: String
    gradeLevel: String
  }

  input AddProgressEntryInput {
    studentId: ID!
    area: ProgressArea!
    goal: String!
    currentLevel: String!
    targetLevel: String!
    progress: ProgressLevel!
    notes: String
  }

  # Queries
  type Query {
    # User queries
    me: User
    user(id: ID!): User
    users(role: UserRole, limit: Int, offset: Int): [User!]!
    
    # Student queries
    student(id: ID!): Student
    students(gradeLevel: String, limit: Int, offset: Int): [Student!]!
    myStudents: [Student!]! # For teachers/parents
    studentBySchoolId(schoolId: String!): Student
    
    # SSO queries
    ssoProviders: [SSOProvider!]!
  }

  # Mutations
  type Mutation {
    # Authentication mutations
    register(input: RegisterInput!): AuthResponse!
    login(input: LoginInput!): AuthResponse!
    refreshToken(refreshToken: String!): AuthTokens!
    logout: String!
    changePassword(input: ChangePasswordInput!): String!
    requestPasswordReset(email: String!): String!
    resetPassword(token: String!, newPassword: String!): String!
    
    # Profile mutations
    updateProfile(input: UpdateProfileInput!): User!
    provideFerpaConsent: User!
    
    # Student mutations
    createStudent(input: CreateStudentInput!): Student!
    updateStudent(id: ID!, input: UpdateStudentInput!): Student!
    addProgressEntry(input: AddProgressEntryInput!): ProgressEntry!
    
    # User management (admin only)
    updateUserRole(userId: ID!, role: UserRole!): User!
    deactivateUser(userId: ID!): User!
    activateUser(userId: ID!): User!
  }

  # Subscriptions (for real-time updates)
  type Subscription {
    studentProgressUpdated(studentId: ID!): ProgressEntry!
    userStatusChanged: User!
  }
`;

module.exports = typeDefs;
