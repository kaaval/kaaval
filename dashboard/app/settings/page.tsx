"use client";
export default function SettingsPage() {

    return (
        <div className="p-2">
            <h1 className="text-3xl font-bold mb-2">Settings</h1>
            <p className="text-text-secondary mb-8">Customize your workspace appearance and preferences.</p>

            <section className="mb-10">
                <h2 className="text-xl font-semibold mb-4 text-primary">Preferences</h2>
                <div className="bg-card p-6 rounded-lg border border-border-color text-text-secondary">
                    <p>No additional settings available at this time.</p>
                </div>
            </section>
        </div >
    );
}
