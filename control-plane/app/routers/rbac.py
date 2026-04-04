from fastapi import APIRouter, Depends, HTTPException
from ..k8s_client import k8s_client
from ..auth import get_current_active_user, User

router = APIRouter(
    prefix="/rbac",
    tags=["rbac"],
    dependencies=[Depends(get_current_active_user)]
)

@router.get("/graph")
def get_rbac_graph(user: User = Depends(get_current_active_user)):
    raw_data = k8s_client.get_rbac_graph_data()
    if "error" in raw_data:
        raise HTTPException(status_code=500, detail=raw_data["error"])
    
    # Process into React Flow elements (Nodes and Edges)
    nodes = []
    edges = []
    y_pos = 0
    
    # 1. Subjects (Users/Groups/SA) -> 2. Bindings -> 3. Roles
    
    # To avoid duplicates, track created nodes
    subject_map = {} # key -> id
    role_map = {}    # key -> id
    binding_map = {} # key -> id

    # Helper to clean names
    def clean_id(s): return s.replace(":", "_").replace(".", "_").replace("/", "_")

    # Process RoleBindings
    for rb in raw_data.get("role_bindings", []):
        rb_id = f"rb_{clean_id(rb['namespace'])}_{clean_id(rb['name'])}"
        
        # Add Binding Node
        if rb_id not in binding_map:
            nodes.append({
                "id": rb_id,
                "data": { "label": f"{rb['name']} (RB)" },
                "position": { "x": 250, "y": y_pos },
                "style": { "background": "#e0f2f1", "border": "1px solid #00695c" } # Teal
            })
            binding_map[rb_id] = True
            y_pos += 50

        # Edges from Subjects -> Binding
        for sub in rb.get("subjects", []):
            sub_id = f"sub_{clean_id(sub.get('kind', 'User'))}_{clean_id(sub.get('name', 'unknown'))}"
            if sub_id not in subject_map:
                nodes.append({
                    "id": sub_id,
                    "data": { "label": f"{sub.get('name')} ({sub.get('kind')})" },
                    "position": { "x": 0, "y": y_pos },
                    "type": "input",
                    "style": { "background": "#e3f2fd", "border": "1px solid #1565c0" } # Blue
                })
                subject_map[sub_id] = True
            edges.append({
                "id": f"edge_{sub_id}_{rb_id}",
                "source": sub_id,
                "target": rb_id,
                "animated": True
            })

        # Edges from Binding -> Role
        role_ref = rb.get("roleRef", {})
        role_name = role_ref.get("name")
        role_kind = role_ref.get("kind")
        # Role ID must include namespace if it's a Role, but RBACRef doesn't strictly say where the role is 
        # (Role is in same NS as Binding, ClusterRole is global)
        role_ns = rb['namespace'] if role_kind == "Role" else "cluster"
        role_id = f"role_{clean_id(role_ns)}_{clean_id(role_name)}"
        
        if role_id not in role_map:
            nodes.append({
                "id": role_id,
                "data": { "label": f"{role_name} ({role_kind})" },
                "position": { "x": 500, "y": y_pos },
                "type": "output",
                "style": { "background": "#fce4ec", "border": "1px solid #c2185b" } # Pink
            })
            role_map[role_id] = True
        
        edges.append({
            "id": f"edge_{rb_id}_{role_id}",
            "source": rb_id,
            "target": role_id
        })

    # Process ClusterRoleBindings (Similar logic)
    for crb in raw_data.get("cluster_role_bindings", []):
        crb_id = f"crb_{clean_id(crb['name'])}"
        
        if crb_id not in binding_map:
            nodes.append({
                "id": crb_id,
                "data": { "label": f"{crb['name']} (CRB)" },
                "position": { "x": 250, "y": y_pos },
                "style": { "background": "#fff3e0", "border": "1px solid #e65100" } # Orange
            })
            binding_map[crb_id] = True
            y_pos += 50

        for sub in crb.get("subjects", []):
            sub_id = f"sub_{clean_id(sub.get('kind', 'User'))}_{clean_id(sub.get('name', 'unknown'))}"
            if sub_id not in subject_map:
                nodes.append({
                    "id": sub_id,
                    "data": { "label": f"{sub.get('name')} ({sub.get('kind')})" },
                    "position": { "x": 0, "y": y_pos },
                    "type": "input",
                     "style": { "background": "#e3f2fd", "border": "1px solid #1565c0" }
                })
                subject_map[sub_id] = True
            edges.append({
                "id": f"edge_{sub_id}_{crb_id}",
                "source": sub_id,
                "target": crb_id,
                "animated": True
            })

        role_ref = crb.get("roleRef", {})
        role_name = role_ref.get("name")
        role_id = f"role_cluster_{clean_id(role_name)}"
        
        if role_id not in role_map:
            nodes.append({
                "id": role_id,
                "data": { "label": f"{role_name} (ClusterRole)" },
                "position": { "x": 500, "y": y_pos },
                "type": "output",
                "style": { "background": "#f3e5f5", "border": "1px solid #7b1fa2" } # Purple
            })
            role_map[role_id] = True
            
        edges.append({
            "id": f"edge_{crb_id}_{role_id}",
            "source": crb_id,
            "target": role_id
        })

    return {"nodes": nodes, "edges": edges}
