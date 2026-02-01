/**
 * CRL Management JavaScript Functions
 */

function showRevokeModal() {
    const modal = new bootstrap.Modal(document.getElementById('revokeModal'));
    modal.show();
}

function showUnrevokeModal() {
    const modal = new bootstrap.Modal(document.getElementById('unrevokeModal'));
    modal.show();
}

function showRegenerateCRLModal() {
    const modal = new bootstrap.Modal(document.getElementById('regenerateCRLModal'));
    modal.show();
}

async function revokeCertificate() {
    const reason = document.getElementById('revocationReason').value;
    const caPassword = document.getElementById('caPassword').value;
    const certId = window.certId; // Set in template

    if (!caPassword) {
        showError('CA password is required');
        return;
    }

    try {
        const response = await fetch(`/api/certs/${certId}/revoke`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                reason: reason,
                ca_password: caPassword
            })
        });

        if (response.ok) {
            showSuccess('Certificate revoked successfully');
            setTimeout(() => location.reload(), 1500);
        } else {
            const data = await response.json();
            showError(data.detail || 'Failed to revoke certificate');
        }
    } catch (error) {
        showError('Error: ' + error.message);
    }
}

async function unrevokeCertificate() {
    const caPassword = document.getElementById('unrevokeCaPassword').value;
    const certId = window.certId;

    if (!caPassword) {
        showError('CA password is required');
        return;
    }

    try {
        const response = await fetch(`/api/certs/${certId}/unrevoke`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ca_password: caPassword
            })
        });

        if (response.ok) {
            showSuccess('Certificate hold removed successfully');
            setTimeout(() => location.reload(), 1500);
        } else {
            const data = await response.json();
            showError(data.detail || 'Failed to remove certificate hold');
        }
    } catch (error) {
        showError('Error: ' + error.message);
    }
}

async function regenerateCRL() {
    const caPassword = document.getElementById('crlCaPassword').value;
    const caId = window.caId; // Set in template

    if (!caPassword) {
        showError('CA password is required');
        return;
    }

    try {
        const response = await fetch(`/api/cas/${caId}/crl/regenerate?ca_password=${encodeURIComponent(caPassword)}`, {
            method: 'POST'
        });

        if (response.ok) {
            showSuccess('CRL regenerated successfully');
            setTimeout(() => location.reload(), 1500);
        } else {
            const data = await response.json();
            showError(data.detail || 'Failed to regenerate CRL');
        }
    } catch (error) {
        showError('Error: ' + error.message);
    }
}
