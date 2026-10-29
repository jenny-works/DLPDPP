rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() {
      return request.auth != null;
    }
    function currentRole() {
      return get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role;
    }
    function canEdit() {
      return signedIn() && (currentRole() == 'admin' || currentRole() == 'editor');
    }
    function isAdmin() {
      return signedIn() && currentRole() == 'admin';
    }
    function validRecord() {
      return request.resource.data.date is string
        && request.resource.data.item_no is string
        && request.resource.data.item_no.size() > 0
        && request.resource.data.item_no.size() <= 100
        && request.resource.data.item_name is string
        && request.resource.data.item_name.size() > 0
        && request.resource.data.item_name.size() <= 200
        && request.resource.data.quantity is number
        && request.resource.data.quantity > 0
        && request.resource.data.quantity <= 1000000000000
        && request.resource.data.project is string
        && request.resource.data.project.size() <= 100
        && request.resource.data.remark is string
        && request.resource.data.remark.size() <= 2000;
    }
    function validBom() {
      return request.resource.data.item_no is string
        && request.resource.data.item_no.size() > 0
        && request.resource.data.item_no.size() <= 100
        && request.resource.data.item_name is string
        && request.resource.data.item_name.size() > 0
        && request.resource.data.item_name.size() <= 200
        && request.resource.data.required_qty is number
        && request.resource.data.required_qty > 0
        && request.resource.data.project is string
        && request.resource.data.project.size() <= 100
        && request.resource.data.remark is string
        && request.resource.data.remark.size() <= 2000;
    }

    match /users/{uid} {
      allow read: if signedIn() && (request.auth.uid == uid || isAdmin());
      allow create: if signedIn()
        && request.auth.uid == uid
        && request.resource.data.role == 'viewer'
        && request.resource.data.email == request.auth.token.email;
      allow update: if isAdmin()
        && (request.resource.data.role == 'admin'
          || request.resource.data.role == 'editor'
          || request.resource.data.role == 'viewer');
      allow delete: if isAdmin() && request.auth.uid != uid;
    }

    match /records/{recordId} {
      allow read: if signedIn();
      allow create, update: if canEdit() && validRecord();
      allow delete: if canEdit();
    }

    match /bom/{bomId} {
      allow read: if signedIn();
      allow create, update: if canEdit() && validBom();
      allow delete: if canEdit();
    }

    match /items/{itemId} {
      allow read: if signedIn();
      allow create, update: if canEdit()
        && request.resource.data.item_no is string
        && request.resource.data.item_name is string;
      allow delete: if isAdmin();
    }

    match /audit_log/{auditId} {
      allow read: if isAdmin();
      allow create: if signedIn()
        && request.resource.data.actor_uid == request.auth.uid;
      allow update, delete: if isAdmin();
    }
  }
}
